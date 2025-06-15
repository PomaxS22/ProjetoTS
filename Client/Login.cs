using EI.SI;
using System;
using System.Net;
using System.Net.Sockets;
using System.Windows.Forms;
using System.Security.Cryptography;
using System.Text;
using System.Drawing;

namespace Client
{
    public partial class Login : Form
    {
        private const int PORT = 10000;
        NetworkStream networkStream;
        ProtocolSI protocolSI;
        TcpClient client;

        // Variáveis de encriptação simples
        private RSACryptoServiceProvider rsa;
        private byte[] aesKey;
        private byte[] aesIV;

        // Variáveis para armazenar informações do utilizador autenticado
        private int loggedUserId = -1;
        private string loggedUsername = null;

        public Login()
        {
            InitializeComponent();

            // Gerar chaves RSA (simples) - IMPORTANTE: Guardar para assinaturas
            rsa = new RSACryptoServiceProvider(2048);
        }

        private void btnLogin_Click(object sender, EventArgs e)
        {
            string username = txtUsername.Text.Trim();
            string password = txtPassword.Text.Trim();

            if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password))
            {
                MessageBox.Show("Por favor, preencha o utilizador e palavra-passe.", "Aviso", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            // Tentar autenticar com encriptação
            if (AuthenticateUserWithEncryption(username, password))
            {
                // Login bem-sucedido - abrir formulário principal do cliente com encriptação
                // NOVO: Passar também as chaves RSA para assinaturas digitais
                Client mainForm = new Client(loggedUserId, loggedUsername, client, networkStream, protocolSI, aesKey, aesIV, rsa);

                this.Hide();
                mainForm.ShowDialog();
                this.Close();
            }
            else
            {
                MessageBox.Show("Utilizador ou palavra-passe incorrectos.", "Erro", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void btnRegister_Click(object sender, EventArgs e)
        {
            string username = txtUsername.Text.Trim();
            string password = txtPassword.Text.Trim();

            if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password))
            {
                MessageBox.Show("Por favor, preencha o utilizador e palavra-passe para registar.", "Aviso", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            if (username.Length < 3)
            {
                MessageBox.Show("O nome de utilizador deve ter pelo menos 3 caracteres.", "Aviso", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            if (password.Length < 3)
            {
                MessageBox.Show("A palavra-passe deve ter pelo menos 3 caracteres.", "Aviso", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            // Tentar registar com encriptação
            if (RegisterUserWithEncryption(username, password))
            {
                MessageBox.Show("Utilizador registado com sucesso! Agora pode fazer login.", "Sucesso", MessageBoxButtons.OK, MessageBoxIcon.Information);

                txtPassword.Clear();
                txtPassword.Focus();
            }
            else
            {
                MessageBox.Show("Erro ao registar utilizador. Nome de utilizador pode já existir.", "Erro", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        /// <summary>
        /// Encriptação simples: Autenticar com RSA+AES + Registo de Chave Pública para Assinaturas
        /// </summary>
        private bool AuthenticateUserWithEncryption(string username, string password)
        {
            try
            {
                // Passo 1: Conectar ao servidor
                ConnectToServer();

                // Passo 2: Trocar chaves (RSA + AES)
                if (!ExchangeKeysSimple())
                {
                    MessageBox.Show("Falha na troca de chaves.", "Erro", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return false;
                }

                // Passo 3: Encriptar credenciais e enviar
                string authData = $"{username}:{password}";
                string encryptedAuth = EncryptWithAES(authData);

                byte[] packet = protocolSI.Make(ProtocolSICmdType.USER_OPTION_1, encryptedAuth);
                networkStream.Write(packet, 0, packet.Length);

                // Passo 4: Aguardar resposta
                networkStream.Read(protocolSI.Buffer, 0, protocolSI.Buffer.Length);

                if (protocolSI.GetCmdType() == ProtocolSICmdType.USER_OPTION_2)
                {
                    // Desencriptar resposta
                    string encryptedResponse = protocolSI.GetStringFromData();
                    string userData = DecryptWithAES(encryptedResponse);

                    string[] parts = userData.Split(':');
                    if (parts.Length >= 2)
                    {
                        loggedUserId = int.Parse(parts[0]);
                        loggedUsername = parts[1];

                        // NOVO: Passo 5 - Registar chave pública RSA no servidor para assinaturas
                        if (!RegisterPublicKeyForSignatures())
                        {
                            MessageBox.Show("Falha ao registar chave para assinaturas.", "Aviso", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                            // Continuar mesmo assim - não é crítico
                        }

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
        /// NOVO: Registar chave pública RSA no servidor para validação de assinaturas
        /// </summary>
        private bool RegisterPublicKeyForSignatures()
        {
            try
            {
                // Enviar chave pública RSA para o servidor guardar para validações futuras
                string publicKeyXml = rsa.ToXmlString(false); // Apenas chave pública
                string keyData = $"REGISTER_SIGNATURE_KEY:{loggedUserId}:{publicKeyXml}";
                string encryptedKeyData = EncryptWithAES(keyData);

                byte[] packet = protocolSI.Make(ProtocolSICmdType.DATA, encryptedKeyData);
                networkStream.Write(packet, 0, packet.Length);

                // Aguardar confirmação
                networkStream.Read(protocolSI.Buffer, 0, protocolSI.Buffer.Length);

                if (protocolSI.GetCmdType() == ProtocolSICmdType.ACK)
                {
                    string response = protocolSI.GetStringFromData();
                    string decryptedResponse = DecryptWithAES(response);
                    return decryptedResponse == "SIGNATURE_KEY_REGISTERED";
                }

                return false;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Erro ao registar chave para assinaturas: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Encriptação simples: Registar com RSA+AES
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
                // Criar ligação separada para registo
                IPEndPoint endpoint = new IPEndPoint(IPAddress.Loopback, PORT);
                registerClient = new TcpClient();
                registerClient.Connect(endpoint);
                registerStream = registerClient.GetStream();
                registerProtocol = new ProtocolSI();
                registerRSA = new RSACryptoServiceProvider(2048);

                // Trocar chaves para registo
                if (!ExchangeKeysForRegistration(registerStream, registerProtocol, registerRSA, out regAESKey, out regAESIV))
                {
                    return false;
                }

                // Encriptar dados de registo
                string regData = $"{username}:{password}";
                string encryptedRegData = EncryptWithAESKeys(regData, regAESKey, regAESIV);

                byte[] packet = registerProtocol.Make(ProtocolSICmdType.USER_OPTION_3, encryptedRegData);
                registerStream.Write(packet, 0, packet.Length);

                // Aguardar resposta
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
                MessageBox.Show("Erro ao registar: " + ex.Message, "Erro", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return false;
            }
            finally
            {
                // Limpeza
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
                catch { /* Ignorar erros de limpeza */ }
            }
        }

        /// <summary>
        /// Troca de chaves simples: Enviar chave pública RSA, receber chave AES encriptada
        /// </summary>
        private bool ExchangeKeysSimple()
        {
            try
            {
                // Enviar chave pública RSA para o servidor
                string publicKeyXml = rsa.ToXmlString(false); // false = apenas chave pública
                byte[] keyPacket = protocolSI.Make(ProtocolSICmdType.DATA, "KEY_EXCHANGE:" + publicKeyXml);
                networkStream.Write(keyPacket, 0, keyPacket.Length);

                // Aguardar chave AES encriptada do servidor
                networkStream.Read(protocolSI.Buffer, 0, protocolSI.Buffer.Length);

                if (protocolSI.GetCmdType() == ProtocolSICmdType.ACK)
                {
                    // Obter chave AES encriptada e desencriptá-la
                    string encryptedAESKeyBase64 = protocolSI.GetStringFromData();
                    byte[] encryptedAESKey = Convert.FromBase64String(encryptedAESKeyBase64);

                    // Desencriptar com a nossa chave privada RSA
                    byte[] decryptedData = rsa.Decrypt(encryptedAESKey, false);

                    // Dividir em chave e IV (primeiros 32 bytes = chave, próximos 16 bytes = IV)
                    aesKey = new byte[32];
                    aesIV = new byte[16];
                    Array.Copy(decryptedData, 0, aesKey, 0, 32);
                    Array.Copy(decryptedData, 32, aesIV, 0, 16);

                    Console.WriteLine("🔐 Chaves AES recebidas e desencriptadas!");
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
        /// Troca de chaves para registo (ligação separada)
        /// </summary>
        private bool ExchangeKeysForRegistration(NetworkStream stream, ProtocolSI protocol, RSACryptoServiceProvider rsaProvider, out byte[] key, out byte[] iv)
        {
            key = null;
            iv = null;

            try
            {
                // Enviar chave pública RSA
                string publicKeyXml = rsaProvider.ToXmlString(false);
                byte[] keyPacket = protocol.Make(ProtocolSICmdType.DATA, "KEY_EXCHANGE:" + publicKeyXml);
                stream.Write(keyPacket, 0, keyPacket.Length);

                // Aguardar chave AES encriptada
                stream.Read(protocol.Buffer, 0, protocol.Buffer.Length);

                if (protocol.GetCmdType() == ProtocolSICmdType.ACK)
                {
                    string encryptedAESKeyBase64 = protocol.GetStringFromData();
                    byte[] encryptedAESKey = Convert.FromBase64String(encryptedAESKeyBase64);

                    // Desencriptar com chave privada RSA
                    byte[] decryptedData = rsaProvider.Decrypt(encryptedAESKey, false);

                    // Dividir em chave e IV
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
        /// Encriptação AES simples
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
        /// Desencriptação AES simples
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
        /// Encriptação AES com chaves específicas (para registo)
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
        /// Desencriptação AES com chaves específicas (para registo)
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
        /// Conectar ao servidor
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

        #region Efeitos de Foco nos TextBoxes

        private void txtUsername_Enter(object sender, EventArgs e)
        {
            TextBox txt = sender as TextBox;
            if (txt != null)
            {
                txt.BackColor = Color.FromArgb(255, 255, 255); // Branco quando focado
            }
        }

        private void txtUsername_Leave(object sender, EventArgs e)
        {
            TextBox txt = sender as TextBox;
            if (txt != null)
            {
                txt.BackColor = Color.FromArgb(248, 249, 250); // Cinza claro quando não focado
            }
        }

        private void txtPassword_Enter(object sender, EventArgs e)
        {
            TextBox txt = sender as TextBox;
            if (txt != null)
            {
                txt.BackColor = Color.FromArgb(255, 255, 255); // Branco quando focado
            }
        }

        private void txtPassword_Leave(object sender, EventArgs e)
        {
            TextBox txt = sender as TextBox;
            if (txt != null)
            {
                txt.BackColor = Color.FromArgb(248, 249, 250); // Cinza claro quando não focado
            }
        }

        #endregion
    }
}