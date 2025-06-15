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
        private bool isRunning = false;

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
            receiveThread = new Thread(ReceiveMessages);
            receiveThread.IsBackground = true;
            receiveThread.Start();
        }

        // Method to receive messages
        private void ReceiveMessages()
        {
            try
            {
                while (isRunning)
                {
                    // Check if data is available
                    if (networkStream.DataAvailable)
                    {
                        // Read message
                        networkStream.Read(protocolSI.Buffer, 0, protocolSI.Buffer.Length);

                        // Check message type
                        if (protocolSI.GetCmdType() == ProtocolSICmdType.DATA)
                        {
                            string message = protocolSI.GetStringFromData();

                            // Update UI with received message
                            UpdateChatBox(message);

                            // Send ACK
                            byte[] ack = protocolSI.Make(ProtocolSICmdType.ACK);
                            networkStream.Write(ack, 0, ack.Length);
                        }
                    }

                    // Small pause to not overload CPU
                    Thread.Sleep(10);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show("Erro ao receber mensagens: " + ex.Message, "Erro", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        // Method to safely update chat box across threads
        private void UpdateChatBox(string message)
        {
            if (txtChatBox.InvokeRequired)
            {
                // If we're on another thread, invoke this method on the UI thread
                txtChatBox.Invoke(new Action<string>(UpdateChatBox), message);
            }
            else
            {
                // We're on the UI thread, can update directly
                txtChatBox.AppendText(message + Environment.NewLine);
                // Scroll to the end
                txtChatBox.SelectionStart = txtChatBox.Text.Length;
                txtChatBox.ScrollToCaret();
            }
        }

        // Send message button click event
        private void buttonSend_Click(object sender, EventArgs e)
        {
            string msg = textBoxMessage.Text;
            if (string.IsNullOrWhiteSpace(msg))
                return;

            textBoxMessage.Clear();
            byte[] packet = protocolSI.Make(ProtocolSICmdType.DATA, msg);
            networkStream.Write(packet, 0, packet.Length);

            // Wait for ACK
            while (protocolSI.GetCmdType() != ProtocolSICmdType.ACK)
            {
                networkStream.Read(protocolSI.Buffer, 0, protocolSI.Buffer.Length);
            }

            // Show sent message in own chat (optional)
            UpdateChatBox($"Eu: {msg}");
        }

        // Method to close client connection
        private void CloseClient()
        {
            try
            {
                // Stop receiving thread
                isRunning = false;
                if (receiveThread != null && receiveThread.IsAlive)
                {
                    receiveThread.Join(1000); // Wait up to 1 second for thread to finish
                }

                if (networkStream != null && client != null && client.Connected)
                {
                    // Send End of Transmission
                    byte[] eot = protocolSI.Make(ProtocolSICmdType.EOT);
                    networkStream.Write(eot, 0, eot.Length);
                    networkStream.Read(protocolSI.Buffer, 0, protocolSI.Buffer.Length);
                    networkStream.Close();
                    client.Close();
                }
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }
        }

        // Form closing event
        private void Client_FormClosing(object sender, FormClosingEventArgs e)
        {
            CloseClient();
        }

        // Quit button click event
        private void buttonQuit_Click(object sender, EventArgs e)
        {
            CloseClient();
            this.Close();
        }
    }
}