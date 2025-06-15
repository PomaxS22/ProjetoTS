using EI.SI;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace Client
{
    public partial class Client : Form
    {
        NetworkStream networkStream;
        ProtocolSI protocolSI;
        TcpClient client;

        // User information received from Login form
        private int loggedUserId = -1;
        private string loggedUsername = null;

        // Thread for receiving messages
        private Thread receiveThread;
        private volatile bool isRunning = false;

        // New constructor that accepts authentication parameters from Login form
        public Client(int userId, string username, TcpClient tcpClient, NetworkStream stream, ProtocolSI protocol)
        {
            InitializeComponent();

            // Set user information
            loggedUserId = userId;
            loggedUsername = username;

            // Set network components
            client = tcpClient;
            networkStream = stream;
            protocolSI = protocol;

            // Update form title with username
            this.Text = $"Chat - {loggedUsername}";

            // Username Label
            labelUserName.Text = loggedUsername;

            // Start receiving messages
            StartReceiving();
        }

        // Start the message receiving thread
        private void StartReceiving()
        {
            isRunning = true;
            receiveThread = new Thread(ReceiveMessages)
            {
                IsBackground = true,
                Name = $"ReceiveThread_{loggedUsername}"
            };
            receiveThread.Start();
        }

        // Method to receive messages - COMPLETELY ISOLATED VERSION
        private void ReceiveMessages()
        {
            try
            {
                while (isRunning && networkStream != null && client != null && client.Connected)
                {
                    try
                    {
                        // Check if data is available
                        if (networkStream.DataAvailable)
                        {
                            // Read message
                            byte[] buffer = new byte[protocolSI.Buffer.Length];
                            int bytesRead = networkStream.Read(buffer, 0, buffer.Length);

                            if (bytesRead > 0)
                            {
                                // Copy to protocol buffer
                                Array.Copy(buffer, protocolSI.Buffer, Math.Min(buffer.Length, protocolSI.Buffer.Length));

                                // Check message type
                                if (protocolSI.GetCmdType() == ProtocolSICmdType.DATA)
                                {
                                    string message = protocolSI.GetStringFromData();

                                    // Update UI with received message - THREAD SAFE
                                    UpdateChatBoxSafe(message);

                                    // Send ACK
                                    byte[] ack = protocolSI.Make(ProtocolSICmdType.ACK);
                                    networkStream.Write(ack, 0, ack.Length);
                                }
                            }
                        }

                        // Small pause to not overload CPU
                        Thread.Sleep(100);
                    }
                    catch (Exception ex)
                    {
                        if (isRunning) // Only log if we're still supposed to be running
                        {
                            Console.WriteLine($"Error in receive thread for {loggedUsername}: {ex.Message}");
                        }
                        Thread.Sleep(1000); // Wait a bit before retrying
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Fatal error in receive thread for {loggedUsername}: {ex.Message}");
            }
        }

        // COMPLETELY SAFE: Thread-safe method to update chat box
        private void UpdateChatBoxSafe(string message)
        {
            try
            {
                if (this.IsDisposed || this.Disposing || !this.IsHandleCreated)
                    return;

                if (this.InvokeRequired)
                {
                    this.BeginInvoke(new Action(() =>
                    {
                        try
                        {
                            if (!this.IsDisposed && txtChatBox != null)
                            {
                                txtChatBox.AppendText(message + Environment.NewLine);
                                txtChatBox.SelectionStart = txtChatBox.Text.Length;
                                txtChatBox.ScrollToCaret();
                            }
                        }
                        catch { /* Ignore UI update errors */ }
                    }));
                }
                else
                {
                    if (txtChatBox != null)
                    {
                        txtChatBox.AppendText(message + Environment.NewLine);
                        txtChatBox.SelectionStart = txtChatBox.Text.Length;
                        txtChatBox.ScrollToCaret();
                    }
                }
            }
            catch
            {
                // Ignore all errors to prevent crashing
            }
        }

        // FIRE AND FORGET: Non-blocking send message
        private void buttonSend_Click(object sender, EventArgs e)
        {
            string msg = textBoxMessage.Text.Trim();
            if (string.IsNullOrWhiteSpace(msg))
                return;

            // Clear immediately
            textBoxMessage.Clear();

            // Send in background - no waiting for ACK
            Task.Run(() =>
            {
                try
                {
                    if (networkStream != null && client != null && client.Connected)
                    {
                        byte[] packet = protocolSI.Make(ProtocolSICmdType.DATA, msg);
                        networkStream.Write(packet, 0, packet.Length);

                        // Show sent message immediately without waiting for ACK
                        UpdateChatBoxSafe($"Eu: {msg}");
                    }
                }
                catch (Exception ex)
                {
                    // Show error if send fails
                    UpdateChatBoxSafe($"[ERRO] Falha ao enviar: {msg}");
                    Console.WriteLine($"Send error for {loggedUsername}: {ex.Message}");
                }
            });

            // Focus back to message input
            textBoxMessage.Focus();
        }

        // CLEAN: Method to close client connection
        private void CloseClient()
        {
            try
            {
                isRunning = false;

                // Close network resources first
                if (networkStream != null)
                {
                    try
                    {
                        if (client != null && client.Connected)
                        {
                            byte[] eot = protocolSI.Make(ProtocolSICmdType.EOT);
                            networkStream.Write(eot, 0, eot.Length);
                        }
                    }
                    catch { /* Ignore */ }

                    networkStream.Close();
                    networkStream = null;
                }

                if (client != null)
                {
                    client.Close();
                    client = null;
                }

                // Wait for thread to finish
                if (receiveThread != null && receiveThread.IsAlive)
                {
                    receiveThread.Join(1000);
                }
            }
            catch
            {
                // Ignore cleanup errors
            }
        }

        // Form closing event
        private void Client_FormClosing(object sender, FormClosingEventArgs e)
        {
            CloseClient();
        }

        // COMPLETELY ISOLATED: Create new login in separate process
        private void btnAddUser_Click(object sender, EventArgs e)
        {
            try
            {
                // Create new login form in separate thread to avoid interference
                Thread newLoginThread = new Thread(() =>
                {
                    try
                    {
                        Application.SetCompatibleTextRenderingDefault(false);
                        Login newLoginForm = new Login();
                        Application.Run(newLoginForm);
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Error creating new login: {ex.Message}");
                    }
                })
                {
                    IsBackground = false
                };

                newLoginThread.Start();
            }
            catch (Exception ex)
            {
                MessageBox.Show("Erro ao abrir nova janela de login: " + ex.Message, "Erro",
                    MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }
    }
}