using EI.SI;
using System;
using System.Net;
using System.Net.Sockets;
using System.Windows.Forms;

namespace Client
{
    public partial class Login : Form
    {
        private const int PORT = 10000;
        NetworkStream networkStream;
        ProtocolSI protocolSI;
        TcpClient client;

        // Variables to store logged user info
        private int loggedUserId = -1;
        private string loggedUsername = null;

        public Login()
        {
            InitializeComponent();
        }

        private void btnLogin_Click(object sender, EventArgs e)
        {
            string username = txtUsername.Text.Trim();
            string password = txtPassword.Text.Trim();

            if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password))
            {
                MessageBox.Show("Por favor, preencha o usuário e senha.", "Aviso", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            // Try to authenticate with the server
            if (AuthenticateUser(username, password))
            {
                // Login successful - open main client form
                Client mainForm = new Client(loggedUserId, loggedUsername, client, networkStream, protocolSI);

                this.Hide(); // Hide login form
                mainForm.ShowDialog(); // Show chat form
                this.Close(); // Close login form when chat is closed
            }
            else
            {
                MessageBox.Show("Usuário ou senha incorretos.", "Erro", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        // Method to register user with server
        private bool RegisterUser(string username, string password)
        {
            TcpClient registerClient = null;
            NetworkStream registerStream = null;
            ProtocolSI registerProtocol = null;

            try
            {
                // Create separate connection for registration
                IPEndPoint endpoint = new IPEndPoint(IPAddress.Loopback, PORT);
                registerClient = new TcpClient();
                registerClient.Connect(endpoint);
                registerStream = registerClient.GetStream();
                registerProtocol = new ProtocolSI();

                // Create registration packet (username:password)
                string regData = $"{username}:{password}";
                byte[] packet = registerProtocol.Make(ProtocolSICmdType.USER_OPTION_3, regData);

                // Send packet
                registerStream.Write(packet, 0, packet.Length);

                // Wait for response
                registerStream.Read(registerProtocol.Buffer, 0, registerProtocol.Buffer.Length);

                // Check response
                if (registerProtocol.GetCmdType() == ProtocolSICmdType.USER_OPTION_4)
                {
                    // Check if registration was successful
                    string responseData = registerProtocol.GetStringFromData();
                    return responseData == "SUCCESS";
                }

                // If we reach here, registration failed
                return false;
            }
            catch (Exception ex)
            {
                MessageBox.Show("Erro ao conectar ao servidor para registro: " + ex.Message, "Erro", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return false;
            }
            finally
            {
                // Clean up registration connection
                try
                {
                    if (registerStream != null)
                    {
                        byte[] eot = registerProtocol.Make(ProtocolSICmdType.EOT);
                        registerStream.Write(eot, 0, eot.Length);
                        registerStream.Read(registerProtocol.Buffer, 0, registerProtocol.Buffer.Length);
                        registerStream.Close();
                    }
                    if (registerClient != null)
                        registerClient.Close();
                }
                catch (Exception)
                {
                    // Ignore cleanup errors
                }
            }
        }

        // Method to authenticate user with server
        private bool AuthenticateUser(string username, string password)
        {
            try
            {
                // Connect to server
                ConnectToServer();

                // Create authentication packet (username:password)
                string authData = $"{username}:{password}";
                byte[] packet = protocolSI.Make(ProtocolSICmdType.USER_OPTION_1, authData);

                // Send packet
                networkStream.Write(packet, 0, packet.Length);

                // Wait for response
                networkStream.Read(protocolSI.Buffer, 0, protocolSI.Buffer.Length);

                // Check response
                if (protocolSI.GetCmdType() == ProtocolSICmdType.USER_OPTION_2)
                {
                    // Authentication successful
                    string userData = protocolSI.GetStringFromData();
                    string[] parts = userData.Split(':');

                    if (parts.Length >= 2)
                    {
                        loggedUserId = int.Parse(parts[0]);
                        loggedUsername = parts[1];
                        return true;
                    }
                }

                // If we reach here, authentication failed
                return false;
            }
            catch (Exception ex)
            {
                MessageBox.Show("Erro ao autenticar: " + ex.Message, "Erro", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return false;
            }
        }

        // Method to connect to server
        private void ConnectToServer()
        {
            try
            {
                IPEndPoint endpoint = new IPEndPoint(IPAddress.Loopback, PORT);
                client = new TcpClient();
                client.Connect(endpoint);
                networkStream = client.GetStream();
                protocolSI = new ProtocolSI();
            }
            catch (Exception ex)
            {
                MessageBox.Show("Erro ao conectar ao servidor: " + ex.Message, "Erro", MessageBoxButtons.OK, MessageBoxIcon.Error);
                throw; // Propagate error to be caught by caller
            }
        }

        private void btnRegister_Click(object sender, EventArgs e)
        {

        }
    }
}