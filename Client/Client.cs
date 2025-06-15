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
using System.Security.Cryptography;

namespace Client
{
    public partial class Client : Form
    {
        NetworkStream networkStream;
        ProtocolSI protocolSI;
        TcpClient client;

        // Simple encryption variables
        private byte[] aesKey;
        private byte[] aesIV;

        // User information received from Login form
        private int loggedUserId = -1;
        private string loggedUsername = null;

        // Thread for receiving messages
        private Thread receiveThread;
        private volatile bool isRunning = false;

        // Updated constructor that accepts AES keys
        public Client(int userId, string username, TcpClient tcpClient, NetworkStream stream, ProtocolSI protocol, byte[] aesKeyParam, byte[] aesIVParam)
        {
            InitializeComponent();

            // Set user information
            loggedUserId = userId;
            loggedUsername = username;

            // Set network components
            client = tcpClient;
            networkStream = stream;
            protocolSI = protocol;

            // Set encryption keys
            aesKey = aesKeyParam;
            aesIV = aesIVParam;

            // Update form title with username
            this.Text = $"Chat Seguro - {loggedUsername}";

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

        // Method to receive encrypted messages
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
                                    try
                                    {
                                        // Get encrypted message and decrypt it
                                        string encryptedMessage = protocolSI.GetStringFromData();
                                        string decryptedMessage = DecryptWithAES(encryptedMessage);

                                        // Update UI with decrypted message
                                        UpdateChatBoxSafe($"🔐 {decryptedMessage}");
                                    }
                                    catch (Exception decryptEx)
                                    {
                                        // If decryption fails, show as encrypted
                                        UpdateChatBoxSafe($"[ENCRYPTED MESSAGE - Error: {decryptEx.Message}]");
                                    }

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

        // Thread-safe method to update chat box
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
                                // Add timestamp
                                string timestampedMessage = $"[{DateTime.Now:HH:mm:ss}] {message}";
                                txtChatBox.AppendText(timestampedMessage + Environment.NewLine);
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
                        // Add timestamp
                        string timestampedMessage = $"[{DateTime.Now:HH:mm:ss}] {message}";
                        txtChatBox.AppendText(timestampedMessage + Environment.NewLine);
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

        // Send encrypted message
        private void buttonSend_Click(object sender, EventArgs e)
        {
            string msg = textBoxMessage.Text.Trim();
            if (string.IsNullOrWhiteSpace(msg))
                return;

            // Clear immediately
            textBoxMessage.Clear();

            // Send encrypted message in background
            Task.Run(() =>
            {
                try
                {
                    if (networkStream != null && client != null && client.Connected)
                    {
                        // Encrypt message with AES
                        string encryptedMessage = EncryptWithAES(msg);

                        // Send encrypted message
                        byte[] packet = protocolSI.Make(ProtocolSICmdType.DATA, encryptedMessage);
                        networkStream.Write(packet, 0, packet.Length);

                        // Show sent message with encryption indicator
                        UpdateChatBoxSafe($"Eu: {msg}");
                    }
                }
                catch (Exception ex)
                {
                    // Show error if send fails
                    UpdateChatBoxSafe($"[ERRO] Falha ao enviar: {msg} - {ex.Message}");
                    Console.WriteLine($"Send error for {loggedUsername}: {ex.Message}");
                }
            });

            // Focus back to message input
            textBoxMessage.Focus();
        }

        /// <summary>
        /// Simple AES encryption for messages
        /// </summary>
        private string EncryptWithAES(string plainText)
        {
            try
            {
                using (AesCryptoServiceProvider aes = new AesCryptoServiceProvider())
                {
                    aes.Key = aesKey;
                    aes.IV = aesIV;

                    ICryptoTransform encryptor = aes.CreateEncryptor();
                    byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
                    byte[] encryptedBytes = encryptor.TransformFinalBlock(plainBytes, 0, plainBytes.Length);
                    return Convert.ToBase64String(encryptedBytes);
                }
            }
            catch (Exception ex)
            {
                throw new Exception($"Encryption failed: {ex.Message}");
            }
        }

        /// <summary>
        /// Simple AES decryption for messages
        /// </summary>
        private string DecryptWithAES(string encryptedText)
        {
            try
            {
                using (AesCryptoServiceProvider aes = new AesCryptoServiceProvider())
                {
                    aes.Key = aesKey;
                    aes.IV = aesIV;

                    ICryptoTransform decryptor = aes.CreateDecryptor();
                    byte[] encryptedBytes = Convert.FromBase64String(encryptedText);
                    byte[] decryptedBytes = decryptor.TransformFinalBlock(encryptedBytes, 0, encryptedBytes.Length);
                    return Encoding.UTF8.GetString(decryptedBytes);
                }
            }
            catch (Exception ex)
            {
                throw new Exception($"Decryption failed: {ex.Message}");
            }
        }

        // Method to close client connection
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

        // Create new login (separate process)
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