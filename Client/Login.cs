using EI.SI;
using System;
using System.Net;
using System.Net.Sockets;
using System.Windows.Forms;
using System.Security.Cryptography;
using System.Text;

namespace Client
{
    public partial class Login : Form
    {
        private const int PORT = 10000;
        NetworkStream networkStream;
        ProtocolSI protocolSI;
        TcpClient client;

        // Simple encryption variables
        private RSACryptoServiceProvider rsa;
        private byte[] aesKey;
        private byte[] aesIV;

        // Variables to store logged user info
        private int loggedUserId = -1;
        private string loggedUsername = null;

        public Login()
        {
            InitializeComponent();

            // Generate RSA keys (simple)
            rsa = new RSACryptoServiceProvider(2048);
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

            // Try to authenticate with encryption
            if (AuthenticateUserWithEncryption(username, password))
            {
                // Login successful - open main client form with encryption
                Client mainForm = new Client(loggedUserId, loggedUsername, client, networkStream, protocolSI, aesKey, aesIV);

                this.Hide();
                mainForm.ShowDialog();
                this.Close();
            }
            else
            {
                MessageBox.Show("Usuário ou senha incorretos.", "Erro", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void btnRegister_Click(object sender, EventArgs e)
        {
            string username = txtUsername.Text.Trim();
            string password = txtPassword.Text.Trim();

            if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password))
            {
                MessageBox.Show("Por favor, preencha o usuário e senha para registrar.", "Aviso", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            if (username.Length < 3)
            {
                MessageBox.Show("O nome de usuário deve ter pelo menos 3 caracteres.", "Aviso", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            if (password.Length < 3)
            {
                MessageBox.Show("A senha deve ter pelo menos 3 caracteres.", "Aviso", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            // Try to register with encryption
            if (RegisterUserWithEncryption(username, password))
            {
                MessageBox.Show("Usuário registrado com sucesso! Agora você pode fazer login.", "Sucesso", MessageBoxButtons.OK, MessageBoxIcon.Information);

                txtPassword.Clear();
                txtPassword.Focus();
            }
            else
            {
                MessageBox.Show("Erro ao registrar usuário. Nome de usuário pode já existir.", "Erro", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        /// <summary>
        /// Simple encryption: Authenticate with RSA+AES
        /// </summary>
        private bool AuthenticateUserWithEncryption(string username, string password)
        {
            try
            {
                // Step 1: Connect to server
                ConnectToServer();

                // Step 2: Exchange keys (RSA + AES)
                if (!ExchangeKeysSimple())
                {
                    MessageBox.Show("Falha na troca de chaves.", "Erro", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return false;
                }

                // Step 3: Encrypt credentials and send
                string authData = $"{username}:{password}";
                string encryptedAuth = EncryptWithAES(authData);

                byte[] packet = protocolSI.Make(ProtocolSICmdType.USER_OPTION_1, encryptedAuth);
                networkStream.Write(packet, 0, packet.Length);

                // Step 4: Wait for response
                networkStream.Read(protocolSI.Buffer, 0, protocolSI.Buffer.Length);

                if (protocolSI.GetCmdType() == ProtocolSICmdType.USER_OPTION_2)
                {
                    // Decrypt response
                    string encryptedResponse = protocolSI.GetStringFromData();
                    string userData = DecryptWithAES(encryptedResponse);

                    string[] parts = userData.Split(':');
                    if (parts.Length >= 2)
                    {
                        loggedUserId = int.Parse(parts[0]);
                        loggedUsername = parts[1];
                        return true;
                    }
                }

                return false;
            }
            catch (Exception ex)
            {
                MessageBox.Show("Erro ao autenticar: " + ex.Message, "Erro", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return false;
            }
        }

        /// <summary>
        /// Simple encryption: Register with RSA+AES
        /// </summary>
        private bool RegisterUserWithEncryption(string username, string password)
        {
            TcpClient registerClient = null;
            NetworkStream registerStream = null;
            ProtocolSI registerProtocol = null;
            RSACryptoServiceProvider registerRSA = null;
            byte[] regAESKey = null;
            byte[] regAESIV = null;

            try
            {
                // Create separate connection for registration
                IPEndPoint endpoint = new IPEndPoint(IPAddress.Loopback, PORT);
                registerClient = new TcpClient();
                registerClient.Connect(endpoint);
                registerStream = registerClient.GetStream();
                registerProtocol = new ProtocolSI();
                registerRSA = new RSACryptoServiceProvider(2048);

                // Exchange keys for registration
                if (!ExchangeKeysForRegistration(registerStream, registerProtocol, registerRSA, out regAESKey, out regAESIV))
                {
                    return false;
                }

                // Encrypt registration data
                string regData = $"{username}:{password}";
                string encryptedRegData = EncryptWithAESKeys(regData, regAESKey, regAESIV);

                byte[] packet = registerProtocol.Make(ProtocolSICmdType.USER_OPTION_3, encryptedRegData);
                registerStream.Write(packet, 0, packet.Length);

                // Wait for response
                registerStream.Read(registerProtocol.Buffer, 0, registerProtocol.Buffer.Length);

                if (registerProtocol.GetCmdType() == ProtocolSICmdType.USER_OPTION_4)
                {
                    string encryptedResponse = registerProtocol.GetStringFromData();
                    string responseData = DecryptWithAESKeys(encryptedResponse, regAESKey, regAESIV);
                    return responseData == "SUCCESS";
                }

                return false;
            }
            catch (Exception ex)
            {
                MessageBox.Show("Erro ao registrar: " + ex.Message, "Erro", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return false;
            }
            finally
            {
                // Cleanup
                try
                {
                    if (registerStream != null)
                    {
                        byte[] eot = registerProtocol.Make(ProtocolSICmdType.EOT);
                        registerStream.Write(eot, 0, eot.Length);
                        registerStream.Read(registerProtocol.Buffer, 0, registerProtocol.Buffer.Length);
                        registerStream.Close();
                    }
                    registerClient?.Close();
                    registerRSA?.Dispose();
                }
                catch { /* Ignore cleanup errors */ }
            }
        }

        /// <summary>
        /// Simple key exchange: Send RSA public key, receive encrypted AES key
        /// </summary>
        private bool ExchangeKeysSimple()
        {
            try
            {
                // Send RSA public key to server
                string publicKeyXml = rsa.ToXmlString(false); // false = public key only
                byte[] keyPacket = protocolSI.Make(ProtocolSICmdType.DATA, "KEY_EXCHANGE:" + publicKeyXml);
                networkStream.Write(keyPacket, 0, keyPacket.Length);

                // Wait for encrypted AES key from server
                networkStream.Read(protocolSI.Buffer, 0, protocolSI.Buffer.Length);

                if (protocolSI.GetCmdType() == ProtocolSICmdType.ACK)
                {
                    // Get encrypted AES key and decrypt it
                    string encryptedAESKeyBase64 = protocolSI.GetStringFromData();
                    byte[] encryptedAESKey = Convert.FromBase64String(encryptedAESKeyBase64);

                    // Decrypt with our RSA private key
                    byte[] decryptedData = rsa.Decrypt(encryptedAESKey, false);

                    // Split into key and IV (first 32 bytes = key, next 16 bytes = IV)
                    aesKey = new byte[32];
                    aesIV = new byte[16];
                    Array.Copy(decryptedData, 0, aesKey, 0, 32);
                    Array.Copy(decryptedData, 32, aesIV, 0, 16);

                    Console.WriteLine("🔐 Chaves AES recebidas e descriptografadas!");
                    return true;
                }

                return false;
            }
            catch (Exception ex)
            {
                MessageBox.Show("Erro na troca de chaves: " + ex.Message, "Erro", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return false;
            }
        }

        /// <summary>
        /// Key exchange for registration (separate connection)
        /// </summary>
        private bool ExchangeKeysForRegistration(NetworkStream stream, ProtocolSI protocol, RSACryptoServiceProvider rsaProvider, out byte[] key, out byte[] iv)
        {
            key = null;
            iv = null;

            try
            {
                // Send RSA public key
                string publicKeyXml = rsaProvider.ToXmlString(false);
                byte[] keyPacket = protocol.Make(ProtocolSICmdType.DATA, "KEY_EXCHANGE:" + publicKeyXml);
                stream.Write(keyPacket, 0, keyPacket.Length);

                // Wait for encrypted AES key
                stream.Read(protocol.Buffer, 0, protocol.Buffer.Length);

                if (protocol.GetCmdType() == ProtocolSICmdType.ACK)
                {
                    string encryptedAESKeyBase64 = protocol.GetStringFromData();
                    byte[] encryptedAESKey = Convert.FromBase64String(encryptedAESKeyBase64);

                    // Decrypt with RSA private key
                    byte[] decryptedData = rsaProvider.Decrypt(encryptedAESKey, false);

                    // Split into key and IV
                    key = new byte[32];
                    iv = new byte[16];
                    Array.Copy(decryptedData, 0, key, 0, 32);
                    Array.Copy(decryptedData, 32, iv, 0, 16);

                    return true;
                }

                return false;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Simple AES encryption
        /// </summary>
        private string EncryptWithAES(string plainText)
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

        /// <summary>
        /// Simple AES decryption
        /// </summary>
        private string DecryptWithAES(string encryptedText)
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

        /// <summary>
        /// AES encryption with specific keys (for registration)
        /// </summary>
        private string EncryptWithAESKeys(string plainText, byte[] key, byte[] iv)
        {
            using (AesCryptoServiceProvider aes = new AesCryptoServiceProvider())
            {
                aes.Key = key;
                aes.IV = iv;

                ICryptoTransform encryptor = aes.CreateEncryptor();
                byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
                byte[] encryptedBytes = encryptor.TransformFinalBlock(plainBytes, 0, plainBytes.Length);
                return Convert.ToBase64String(encryptedBytes);
            }
        }

        /// <summary>
        /// AES decryption with specific keys (for registration)
        /// </summary>
        private string DecryptWithAESKeys(string encryptedText, byte[] key, byte[] iv)
        {
            using (AesCryptoServiceProvider aes = new AesCryptoServiceProvider())
            {
                aes.Key = key;
                aes.IV = iv;

                ICryptoTransform decryptor = aes.CreateDecryptor();
                byte[] encryptedBytes = Convert.FromBase64String(encryptedText);
                byte[] decryptedBytes = decryptor.TransformFinalBlock(encryptedBytes, 0, encryptedBytes.Length);
                return Encoding.UTF8.GetString(decryptedBytes);
            }
        }

        /// <summary>
        /// Connect to server
        /// </summary>
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
                throw;
            }
        }
    }
}