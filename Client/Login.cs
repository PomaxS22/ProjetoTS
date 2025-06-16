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

        // Variáveis para criptografia
        private RSACryptoServiceProvider rsa;
        private byte[] aesKey;
        private byte[] aesIV;

        // Dados do utilizador após login
        private int loggedUserId = -1;
        private string loggedUsername = null;

        public Login()
        {
            InitializeComponent();
            // Gerar chaves RSA para este cliente (usadas para troca de chaves e assinaturas)
            rsa = new RSACryptoServiceProvider(2048);
        }

        private void btnLogin_Click(object sender, EventArgs e)
        {
            string username = txtUsername.Text.Trim();
            string password = txtPassword.Text.Trim();

            if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password))
            {
                MessageBox.Show("Preencha o utilizador e palavra-passe.", "Aviso", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            // Tentar fazer login com criptografia
            if (AuthenticateUser(username, password))
            {
                // Login bem-sucedido - abrir janela principal do chat
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
                MessageBox.Show("Preencha o utilizador e palavra-passe para registar.", "Aviso", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            if (username.Length < 3 || password.Length < 3)
            {
                MessageBox.Show("Utilizador e palavra-passe devem ter pelo menos 3 caracteres.", "Aviso", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            // Tentar registar novo utilizador
            if (RegisterUser(username, password))
            {
                MessageBox.Show("Utilizador registado com sucesso! Pode agora fazer login.", "Sucesso", MessageBoxButtons.OK, MessageBoxIcon.Information);
                txtPassword.Clear();
                txtPassword.Focus();
            }
            else
            {
                MessageBox.Show("Erro ao registar. O nome de utilizador pode já existir.", "Erro", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        // Autenticar utilizador com criptografia
        private bool AuthenticateUser(string username, string password)
        {
            try
            {
                // Ligar ao servidor
                ConnectToServer();
                Console.WriteLine("Ligado ao servidor");

                // Trocar chaves de criptografia (RSA + AES)
                if (!ExchangeKeys())
                {
                    MessageBox.Show("Falha na troca de chaves.", "Erro", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return false;
                }

                Console.WriteLine("Criptografia estabelecida com sucesso");

                // Encriptar credenciais e enviar
                string authData = $"{username}:{password}";
                string encryptedAuth = EncryptWithAES(authData);

                byte[] packet = protocolSI.Make(ProtocolSICmdType.USER_OPTION_1, encryptedAuth);
                networkStream.Write(packet, 0, packet.Length);

                Console.WriteLine($"Credenciais enviadas para: {username}");

                // Aguardar resposta do servidor
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

                        Console.WriteLine($"Login bem-sucedido: {loggedUsername} (ID: {loggedUserId})");

                        // Registar chave pública para assinaturas digitais
                        RegisterPublicKeyForSignatures();
                        return true;
                    }
                }

                Console.WriteLine($"Login falhado para: {username}");
                return false;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Erro ao autenticar: {ex.Message}");
                MessageBox.Show("Erro ao autenticar: " + ex.Message, "Erro", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return false;
            }
        }

        // Registar chave pública no servidor para validar assinaturas
        private bool RegisterPublicKeyForSignatures()
        {
            try
            {
                string publicKeyXml = rsa.ToXmlString(false); // Apenas chave pública
                string keyData = $"REGISTER_SIGNATURE_KEY:{loggedUserId}:{publicKeyXml}";
                string encryptedKeyData = EncryptWithAES(keyData);

                byte[] packet = protocolSI.Make(ProtocolSICmdType.DATA, encryptedKeyData);
                networkStream.Write(packet, 0, packet.Length);

                Console.WriteLine($"Enviada chave pública para assinaturas (utilizador {loggedUserId})");

                // Aguardar confirmação
                networkStream.Read(protocolSI.Buffer, 0, protocolSI.Buffer.Length);

                if (protocolSI.GetCmdType() == ProtocolSICmdType.ACK)
                {
                    string response = protocolSI.GetStringFromData();
                    string decryptedResponse = DecryptWithAES(response);
                    bool success = decryptedResponse == "SIGNATURE_KEY_REGISTERED";

                    if (success)
                        Console.WriteLine("Chave para assinaturas registada com sucesso");
                    else
                        Console.WriteLine("Falha ao registar chave para assinaturas");

                    return success;
                }
                return false;
            }
            catch
            {
                Console.WriteLine("Erro ao registar chave para assinaturas");
                return false; // Não é crítico se falhar
            }
        }

        // Registar novo utilizador
        private bool RegisterUser(string username, string password)
        {
            TcpClient registerClient = null;
            NetworkStream registerStream = null;
            ProtocolSI registerProtocol = null;
            RSACryptoServiceProvider registerRSA = null;
            byte[] regAESKey = null;
            byte[] regAESIV = null;

            try
            {
                Console.WriteLine($"Iniciando registo para: {username}");

                // Criar ligação separada para registo
                IPEndPoint endpoint = new IPEndPoint(IPAddress.Loopback, PORT);
                registerClient = new TcpClient();
                registerClient.Connect(endpoint);
                registerStream = registerClient.GetStream();
                registerProtocol = new ProtocolSI();
                registerRSA = new RSACryptoServiceProvider(2048);

                Console.WriteLine("Ligação para registo estabelecida");

                // Trocar chaves para registo
                if (!ExchangeKeysForRegistration(registerStream, registerProtocol, registerRSA, out regAESKey, out regAESIV))
                {
                    Console.WriteLine("Falha na troca de chaves para registo");
                    return false;
                }

                Console.WriteLine("Criptografia para registo estabelecida");

                // Encriptar dados de registo
                string regData = $"{username}:{password}";
                string encryptedRegData = EncryptWithAESKeys(regData, regAESKey, regAESIV);

                byte[] packet = registerProtocol.Make(ProtocolSICmdType.USER_OPTION_3, encryptedRegData);
                registerStream.Write(packet, 0, packet.Length);

                Console.WriteLine($"Dados de registo enviados para: {username}");

                // Aguardar resposta
                registerStream.Read(registerProtocol.Buffer, 0, registerProtocol.Buffer.Length);

                if (registerProtocol.GetCmdType() == ProtocolSICmdType.USER_OPTION_4)
                {
                    string encryptedResponse = registerProtocol.GetStringFromData();
                    string responseData = DecryptWithAESKeys(encryptedResponse, regAESKey, regAESIV);
                    bool success = responseData == "SUCCESS";

                    if (success)
                        Console.WriteLine($"Registo bem-sucedido: {username}");
                    else
                        Console.WriteLine($"Registo falhado: {username}");

                    return success;
                }

                Console.WriteLine($"Resposta inválida do servidor para registo de: {username}");
                return false;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Erro ao registar {username}: {ex.Message}");
                MessageBox.Show("Erro ao registar: " + ex.Message, "Erro", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return false;
            }
            finally
            {
                // Limpeza da ligação de registo
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
                catch { }
            }
        }

        // Trocar chaves: enviar RSA pública, receber AES encriptada
        private bool ExchangeKeys()
        {
            try
            {
                // Enviar chave pública RSA para o servidor
                string publicKeyXml = rsa.ToXmlString(false);
                byte[] keyPacket = protocolSI.Make(ProtocolSICmdType.DATA, "KEY_EXCHANGE:" + publicKeyXml);
                networkStream.Write(keyPacket, 0, keyPacket.Length);

                // Aguardar chave AES encriptada do servidor
                networkStream.Read(protocolSI.Buffer, 0, protocolSI.Buffer.Length);

                if (protocolSI.GetCmdType() == ProtocolSICmdType.ACK)
                {
                    // Obter e desencriptar chave AES
                    string encryptedAESKeyBase64 = protocolSI.GetStringFromData();
                    byte[] encryptedAESKey = Convert.FromBase64String(encryptedAESKeyBase64);

                    // Desencriptar com a nossa chave privada RSA
                    byte[] decryptedData = rsa.Decrypt(encryptedAESKey, false);

                    // Separar chave e IV (32 bytes chave + 16 bytes IV)
                    aesKey = new byte[32];
                    aesIV = new byte[16];
                    Array.Copy(decryptedData, 0, aesKey, 0, 32);
                    Array.Copy(decryptedData, 32, aesIV, 0, 16);

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

        // Troca de chaves para registo (ligação separada)
        private bool ExchangeKeysForRegistration(NetworkStream stream, ProtocolSI protocol, RSACryptoServiceProvider rsaProvider, out byte[] key, out byte[] iv)
        {
            key = null;
            iv = null;

            try
            {
                string publicKeyXml = rsaProvider.ToXmlString(false);
                byte[] keyPacket = protocol.Make(ProtocolSICmdType.DATA, "KEY_EXCHANGE:" + publicKeyXml);
                stream.Write(keyPacket, 0, keyPacket.Length);

                stream.Read(protocol.Buffer, 0, protocol.Buffer.Length);

                if (protocol.GetCmdType() == ProtocolSICmdType.ACK)
                {
                    string encryptedAESKeyBase64 = protocol.GetStringFromData();
                    byte[] encryptedAESKey = Convert.FromBase64String(encryptedAESKeyBase64);
                    byte[] decryptedData = rsaProvider.Decrypt(encryptedAESKey, false);

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

        // Encriptar texto com AES
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

        // Desencriptar texto com AES
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

        // Encriptar com chaves específicas (para registo)
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

        // Desencriptar com chaves específicas (para registo)
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

        // Ligar ao servidor
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