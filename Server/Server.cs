using EI.SI;
using Server.Data;
using Server.Models;
using System;
using System.Collections.Generic;
using System.Data.Entity;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Security.Cryptography;
using System.Text;
using System.IO;

namespace Server
{
    class Server
    {
        private const int PORT = 10000;
        private const int SALTSIZE = 8;
        private const int NUMBER_OF_ITERATIONS = 50000;

        // Sistema de logging
        private static readonly string LOG_FILE_PATH = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "log.txt");
        private static readonly object logLock = new object();

        // Lista de clientes ligados
        public static readonly List<ClientHandler> connectedClients = new List<ClientHandler>();

        // Chaves públicas para validação de assinaturas
        private static readonly Dictionary<int, RSACryptoServiceProvider> userPublicKeys = new Dictionary<int, RSACryptoServiceProvider>();
        private static readonly object publicKeysLock = new object();

        // Escrever no log
        public static void WriteLog(string message)
        {
            try
            {
                lock (logLock)
                {
                    string timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
                    string logEntry = $"[{timestamp}] {message}";
                    File.AppendAllText(LOG_FILE_PATH, logEntry + Environment.NewLine);
                    Console.WriteLine(logEntry);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Erro ao escrever log: {ex.Message}");
            }
        }

        // Gerar salt para password
        public static byte[] GenerateSalt()
        {
            RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
            byte[] buff = new byte[SALTSIZE];
            rng.GetBytes(buff);
            WriteLog($"Salt gerado ({SALTSIZE} bytes)");
            return buff;
        }

        // Gerar hash da password com salt
        public static byte[] GenerateSaltedHash(string password, byte[] salt)
        {
            Rfc2898DeriveBytes rfc2898 = new Rfc2898DeriveBytes(password, salt, NUMBER_OF_ITERATIONS);
            byte[] hash = rfc2898.GetBytes(32); // hash de 256-bit
            WriteLog($"Hash PBKDF2 gerado ({hash.Length * 8} bits, {NUMBER_OF_ITERATIONS} iterações)");
            return hash;
        }

        // Verificar password
        public static bool VerifyPassword(string password, byte[] storedHash, byte[] storedSalt)
        {
            try
            {
                byte[] computedHash = GenerateSaltedHash(password, storedSalt);
                bool isValid = storedHash.SequenceEqual(computedHash);
                WriteLog($"Verificação de password: {(isValid ? "SUCESSO" : "FALHADO")}");
                return isValid;
            }
            catch
            {
                WriteLog("Erro na verificação de password");
                return false;
            }
        }

        // Registar chave pública para assinaturas
        public static bool RegisterUserPublicKey(int userId, string publicKeyXml)
        {
            try
            {
                lock (publicKeysLock)
                {
                    if (userPublicKeys.ContainsKey(userId))
                    {
                        userPublicKeys[userId].Dispose();
                        userPublicKeys.Remove(userId);
                    }

                    RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
                    rsa.FromXmlString(publicKeyXml);
                    userPublicKeys[userId] = rsa;
                    WriteLog($"Chave pública registada para utilizador {userId}");
                    return true;
                }
            }
            catch
            {
                WriteLog($"Erro ao registar chave pública do utilizador {userId}");
                return false;
            }
        }

        // Verificar assinatura digital
        public static bool VerifyMessageSignature(string message, string signatureBase64, int senderId)
        {
            try
            {
                lock (publicKeysLock)
                {
                    if (!userPublicKeys.ContainsKey(senderId))
                    {
                        WriteLog($"Chave pública não encontrada para utilizador {senderId}");
                        return false;
                    }

                    RSACryptoServiceProvider senderPublicKey = userPublicKeys[senderId];
                    byte[] messageBytes = Encoding.UTF8.GetBytes(message);
                    byte[] signature = Convert.FromBase64String(signatureBase64);

                    bool isValid = senderPublicKey.VerifyData(messageBytes, new SHA256CryptoServiceProvider(), signature);
                    WriteLog($"Verificação de assinatura do utilizador {senderId}: {(isValid ? "VÁLIDA" : "INVÁLIDA")}");
                    return isValid;
                }
            }
            catch
            {
                WriteLog($"Erro na verificação de assinatura do utilizador {senderId}");
                return false;
            }
        }

        // Obter todas as chaves públicas
        public static string GetAllPublicKeysForDistribution()
        {
            try
            {
                lock (publicKeysLock)
                {
                    List<string> keyEntries = new List<string>();
                    foreach (var keyPair in userPublicKeys)
                    {
                        int userId = keyPair.Key;
                        string publicKeyXml = keyPair.Value.ToXmlString(false);
                        keyEntries.Add($"{userId}:{publicKeyXml}");
                    }
                    WriteLog($"Enviando {keyEntries.Count} chaves públicas");
                    return "PUBLIC_KEYS:" + string.Join("|", keyEntries);
                }
            }
            catch
            {
                WriteLog("Erro ao preparar chaves públicas");
                return "PUBLIC_KEYS:";
            }
        }

        // Adicionar cliente à lista
        public static void AddClient(ClientHandler client)
        {
            lock (connectedClients)
            {
                connectedClients.Add(client);
                WriteLog($"➕ Cliente {client.ClientID} ligado. Total: {connectedClients.Count}");
            }
        }

        // Remover cliente da lista
        public static void RemoveClient(ClientHandler client)
        {
            lock (connectedClients)
            {
                connectedClients.Remove(client);
                WriteLog($"➖ Cliente {client.ClientID} desligou. Total: {connectedClients.Count}");
            }
        }

        // Enviar mensagem para todos os clientes
        public static void BroadcastMessage(string message, int excludeClientId = -1)
        {
            lock (connectedClients)
            {
                WriteLog($"📢 Broadcasting para {connectedClients.Count} clientes: {message}");
                foreach (var client in connectedClients)
                {
                    if (client.ClientID != excludeClientId)
                    {
                        client.SendMessage(message);
                    }
                }
            }
        }

        // Enviar chaves públicas para um cliente
        public static void SendPublicKeysToClient(ClientHandler client)
        {
            try
            {
                string publicKeysData = GetAllPublicKeysForDistribution();
                client.SendMessage(publicKeysData);
                WriteLog($"Chaves públicas enviadas para cliente {client.ClientID}");
            }
            catch (Exception ex)
            {
                WriteLog($"Erro ao enviar chaves para cliente {client.ClientID}: {ex.Message}");
            }
        }

        static void Main(string[] args)
        {
            try
            {
                WriteLog("=== SERVIDOR INICIADO ===");

                // Configurar base de dados
                AppDomain.CurrentDomain.SetData("DataDirectory",
                    System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "App_Data"));

                string dataDir = AppDomain.CurrentDomain.GetData("DataDirectory").ToString();
                if (!System.IO.Directory.Exists(dataDir))
                    System.IO.Directory.CreateDirectory(dataDir);

                Database.SetInitializer(new CreateDatabaseIfNotExists<ApplicationDbContext>());

                using (var dbContext = new ApplicationDbContext())
                {
                    dbContext.Database.CreateIfNotExists();
                    int userCount = dbContext.Users.Count();
                    WriteLog($"Base de dados pronta com {userCount} utilizadores");

                    IPEndPoint endpoint = new IPEndPoint(IPAddress.Any, PORT);
                    TcpListener listener = new TcpListener(endpoint);
                    listener.Start();
                    WriteLog($"Servidor a escutar na porta {PORT}");

                    int clientCounter = 0;

                    while (true)
                    {
                        TcpClient client = listener.AcceptTcpClient();
                        clientCounter++;
                        WriteLog($"Cliente {clientCounter} ligado de {client.Client.RemoteEndPoint}");

                        ClientHandler clientHandler = new ClientHandler(client, clientCounter);
                        clientHandler.Handle();
                    }
                }
            }
            catch (Exception ex)
            {
                WriteLog($"ERRO CRÍTICO no servidor: {ex.Message}");
            }
            finally
            {
                // Limpar chaves RSA
                lock (publicKeysLock)
                {
                    foreach (var keyPair in userPublicKeys)
                        keyPair.Value.Dispose();
                    userPublicKeys.Clear();
                }
                WriteLog("=== SERVIDOR ENCERRADO ===");
                Console.WriteLine("Prima qualquer tecla para sair...");
                Console.ReadKey();
            }
        }
    }

    class ClientHandler
    {
        private TcpClient client;
        private int clientID;
        private int _userId = -1; // ID do utilizador autenticado
        private string _username = null; // Nome do utilizador

        // Variáveis de criptografia
        private byte[] aesKey;
        private byte[] aesIV;
        private bool isEncryptionEstablished = false;

        public int ClientID { get { return clientID; } }

        public ClientHandler(TcpClient client, int clientID)
        {
            this.client = client;
            this.clientID = clientID;
            Server.AddClient(this);
        }

        // Enviar mensagem para este cliente
        public void SendMessage(string message)
        {
            try
            {
                NetworkStream ns = client.GetStream();
                ProtocolSI ps = new ProtocolSI();

                if (isEncryptionEstablished)
                {
                    string encryptedMessage = EncryptWithAES(message);
                    byte[] packet = ps.Make(ProtocolSICmdType.DATA, encryptedMessage);
                    ns.Write(packet, 0, packet.Length);
                }
                else
                {
                    byte[] packet = ps.Make(ProtocolSICmdType.DATA, message);
                    ns.Write(packet, 0, packet.Length);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Erro ao enviar para cliente {clientID}: {ex.Message}");
            }
        }

        // Gerar e encriptar chave AES
        private byte[] GenerateAndEncryptAESKey(string clientPublicKeyXml)
        {
            using (AesCryptoServiceProvider aes = new AesCryptoServiceProvider())
            {
                aes.KeySize = 256;
                aes.GenerateKey();
                aes.GenerateIV();

                aesKey = new byte[aes.Key.Length];
                aesIV = new byte[aes.IV.Length];
                Array.Copy(aes.Key, aesKey, aes.Key.Length);
                Array.Copy(aes.IV, aesIV, aes.IV.Length);

                Server.WriteLog($"Chave AES gerada para cliente {clientID} ({aes.KeySize} bits)");

                // Combinar chave + IV
                byte[] combined = new byte[aesKey.Length + aesIV.Length];
                Array.Copy(aesKey, 0, combined, 0, aesKey.Length);
                Array.Copy(aesIV, 0, combined, aesKey.Length, aesIV.Length);

                // Encriptar com RSA do cliente
                using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
                {
                    rsa.FromXmlString(clientPublicKeyXml);
                    byte[] encrypted = rsa.Encrypt(combined, false);
                    Server.WriteLog($"Chave AES encriptada com RSA para cliente {clientID}");
                    return encrypted;
                }
            }
        }

        // Encriptar com AES
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

        // Desencriptar com AES
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

        // Verificar password do utilizador
        private bool VerifyUserPassword(User user, string inputPassword)
        {
            try
            {
                string[] passwordParts = user.Password.Split(':');
                if (passwordParts.Length == 2)
                {
                    // Formato hash:salt
                    byte[] storedHash = Convert.FromBase64String(passwordParts[0]);
                    byte[] storedSalt = Convert.FromBase64String(passwordParts[1]);
                    return Server.VerifyPassword(inputPassword, storedHash, storedSalt);
                }
                else
                {
                    // Password em texto simples (compatibilidade)
                    return user.Password == inputPassword;
                }
            }
            catch
            {
                return false;
            }
        }

        public void Handle()
        {
            Thread thread = new Thread(ThreadHandler);
            thread.Start();
        }

        private void ThreadHandler()
        {
            NetworkStream networkStream = null;
            ProtocolSI protocolSI = new ProtocolSI();

            try
            {
                networkStream = this.client.GetStream();

                while (protocolSI.GetCmdType() != ProtocolSICmdType.EOT)
                {
                    networkStream.Read(protocolSI.Buffer, 0, protocolSI.Buffer.Length);

                    switch (protocolSI.GetCmdType())
                    {
                        case ProtocolSICmdType.DATA:
                            ProcessData(protocolSI.GetStringFromData(), networkStream, protocolSI);
                            break;

                        case ProtocolSICmdType.USER_OPTION_1: // Login
                            ProcessLogin(protocolSI.GetStringFromData(), networkStream, protocolSI);
                            break;

                        case ProtocolSICmdType.USER_OPTION_3: // Registo
                            ProcessRegister(protocolSI.GetStringFromData(), networkStream, protocolSI);
                            break;

                        case ProtocolSICmdType.EOT:
                            byte[] ack = protocolSI.Make(ProtocolSICmdType.ACK);
                            networkStream.Write(ack, 0, ack.Length);
                            break;
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Erro no cliente {clientID}: {ex.Message}");
            }
            finally
            {
                // Limpeza e notificação
                Server.RemoveClient(this);
                if (_userId > 0 && _username != null)
                {
                    Server.WriteLog($"Utilizador {_username} (ID: {_userId}) saiu do chat");
                    Server.BroadcastMessage($"*** {_username} saiu do chat ***");
                }

                try { client.Close(); } catch { }
            }
        }

        // Processar dados recebidos
        private void ProcessData(string rawData, NetworkStream networkStream, ProtocolSI protocolSI)
        {
            if (rawData.StartsWith("KEY_EXCHANGE:"))
            {
                // Troca de chaves
                try
                {
                    string clientPublicKeyXml = rawData.Substring("KEY_EXCHANGE:".Length);
                    Server.WriteLog($"Recebida chave pública RSA do cliente {clientID}");

                    byte[] encryptedAESKey = GenerateAndEncryptAESKey(clientPublicKeyXml);
                    string encryptedKeyBase64 = Convert.ToBase64String(encryptedAESKey);

                    byte[] ack = protocolSI.Make(ProtocolSICmdType.ACK, encryptedKeyBase64);
                    networkStream.Write(ack, 0, ack.Length);
                    isEncryptionEstablished = true;
                    Server.WriteLog($"Criptografia AES estabelecida com cliente {clientID}");
                }
                catch
                {
                    Server.WriteLog($"Erro ao estabelecer criptografia com cliente {clientID}");
                    byte[] ack = protocolSI.Make(ProtocolSICmdType.ACK, "ERROR");
                    networkStream.Write(ack, 0, ack.Length);
                }
            }
            else
            {
                // Processar mensagem normal ou comando especial
                string decryptedData = isEncryptionEstablished ? DecryptWithAES(rawData) : rawData;

                if (decryptedData.StartsWith("REGISTER_SIGNATURE_KEY:"))
                {
                    ProcessSignatureKeyRegistration(decryptedData, networkStream, protocolSI);
                }
                else if (decryptedData.StartsWith("REQUEST_PUBLIC_KEYS"))
                {
                    Server.WriteLog($"Cliente {clientID} solicitou chaves públicas");
                    Server.SendPublicKeysToClient(this);
                    byte[] ack = protocolSI.Make(ProtocolSICmdType.ACK);
                    networkStream.Write(ack, 0, ack.Length);
                }
                else if (decryptedData.StartsWith("SIGNED_MESSAGE:"))
                {
                    ProcessSignedMessage(decryptedData, networkStream, protocolSI);
                }
                else
                {
                    // Mensagem normal
                    string formattedMessage = _userId > 0 ? $"{_username}: {decryptedData}" : $"Cliente {clientID}: {decryptedData}";
                    Server.WriteLog($"Mensagem de {(_userId > 0 ? _username : "cliente " + clientID)}: {decryptedData}");
                    Server.BroadcastMessage(formattedMessage, clientID);

                    byte[] ack = protocolSI.Make(ProtocolSICmdType.ACK);
                    networkStream.Write(ack, 0, ack.Length);
                }
            }
        }

        // Processar login
        private void ProcessLogin(string authData, NetworkStream networkStream, ProtocolSI protocolSI)
        {
            try
            {
                if (isEncryptionEstablished)
                    authData = DecryptWithAES(authData);

                string[] credentials = authData.Split(':');
                if (credentials.Length == 2)
                {
                    string username = credentials[0];
                    string password = credentials[1];

                    Server.WriteLog($"Tentativa de login: {username} (cliente {clientID})");

                    using (var dbContext = new ApplicationDbContext())
                    {
                        var user = dbContext.Users.FirstOrDefault(u => u.Username == username);

                        if (user != null && VerifyUserPassword(user, password))
                        {
                            // Login bem-sucedido
                            _userId = user.Id;
                            _username = user.Username;

                            Server.WriteLog($"Login bem-sucedido: {username} (ID: {_userId})");

                            string responseData = $"{user.Id}:{user.Username}";
                            if (isEncryptionEstablished)
                                responseData = EncryptWithAES(responseData);

                            byte[] response = protocolSI.Make(ProtocolSICmdType.USER_OPTION_2, responseData);
                            networkStream.Write(response, 0, response.Length);

                            Server.BroadcastMessage($"!!! {username} entrou no chat !!!", clientID);
                        }
                        else
                        {
                            // Login falhado
                            Server.WriteLog($"Login falhado: {username} (cliente {clientID})");
                            byte[] response = protocolSI.Make(ProtocolSICmdType.ACK);
                            networkStream.Write(response, 0, response.Length);
                        }
                    }
                }
            }
            catch
            {
                Server.WriteLog($"Erro no processamento de login do cliente {clientID}");
                byte[] response = protocolSI.Make(ProtocolSICmdType.ACK);
                networkStream.Write(response, 0, response.Length);
            }
        }

        // Processar registo
        private void ProcessRegister(string regData, NetworkStream networkStream, ProtocolSI protocolSI)
        {
            try
            {
                if (isEncryptionEstablished)
                    regData = DecryptWithAES(regData);

                string[] credentials = regData.Split(':');
                if (credentials.Length == 2)
                {
                    string username = credentials[0];
                    string password = credentials[1];

                    Server.WriteLog($"Tentativa de registo: {username} (cliente {clientID})");

                    using (var dbContext = new ApplicationDbContext())
                    {
                        var existingUser = dbContext.Users.FirstOrDefault(u => u.Username == username);
                        string responseMessage = "FAILURE";

                        if (existingUser == null)
                        {
                            try
                            {
                                // Criar utilizador com password hash
                                byte[] salt = Server.GenerateSalt();
                                byte[] hash = Server.GenerateSaltedHash(password, salt);

                                var newUser = new User
                                {
                                    Username = username,
                                    Password = $"{Convert.ToBase64String(hash)}:{Convert.ToBase64String(salt)}"
                                };

                                dbContext.Users.Add(newUser);
                                dbContext.SaveChanges();
                                responseMessage = "SUCCESS";
                                Server.WriteLog($"Utilizador registado: {username}");
                            }
                            catch
                            {
                                Server.WriteLog($"Erro ao registar utilizador: {username}");
                            }
                        }
                        else
                        {
                            Server.WriteLog($"Registo falhado - utilizador já existe: {username}");
                        }

                        if (isEncryptionEstablished)
                            responseMessage = EncryptWithAES(responseMessage);

                        byte[] response = protocolSI.Make(ProtocolSICmdType.USER_OPTION_4, responseMessage);
                        networkStream.Write(response, 0, response.Length);
                    }
                }
            }
            catch
            {
                Server.WriteLog($"Erro no processamento de registo do cliente {clientID}");
                string errorMsg = isEncryptionEstablished ? EncryptWithAES("FAILURE") : "FAILURE";
                byte[] response = protocolSI.Make(ProtocolSICmdType.USER_OPTION_4, errorMsg);
                networkStream.Write(response, 0, response.Length);
            }
        }

        // Processar registo de chave para assinaturas
        private void ProcessSignatureKeyRegistration(string data, NetworkStream networkStream, ProtocolSI protocolSI)
        {
            try
            {
                string[] parts = data.Split(new char[] { ':' }, 3);
                if (parts.Length == 3)
                {
                    int userId = int.Parse(parts[1]);
                    string publicKeyXml = parts[2];

                    if (userId == _userId)
                    {
                        bool success = Server.RegisterUserPublicKey(userId, publicKeyXml);
                        string responseMessage = success ? "SIGNATURE_KEY_REGISTERED" : "SIGNATURE_KEY_ERROR";
                        string encryptedResponse = EncryptWithAES(responseMessage);

                        byte[] response = protocolSI.Make(ProtocolSICmdType.ACK, encryptedResponse);
                        networkStream.Write(response, 0, response.Length);

                        if (success)
                        {
                            Server.WriteLog($"Chave para assinaturas registada para {_username} (ID: {_userId})");
                            // Enviar chaves actualizadas para todos
                            foreach (var client in Server.connectedClients)
                                Server.SendPublicKeysToClient(client);
                        }
                    }
                    else
                    {
                        Server.WriteLog($"Tentativa de registar chave para utilizador incorrecto (cliente {clientID})");
                    }
                }
            }
            catch
            {
                Server.WriteLog($"Erro ao processar registo de chave de assinatura (cliente {clientID})");
                string encryptedError = EncryptWithAES("SIGNATURE_KEY_ERROR");
                byte[] response = protocolSI.Make(ProtocolSICmdType.ACK, encryptedError);
                networkStream.Write(response, 0, response.Length);
            }
        }

        // Processar mensagem assinada
        private void ProcessSignedMessage(string data, NetworkStream networkStream, ProtocolSI protocolSI)
        {
            try
            {
                string[] parts = data.Split(new char[] { ':' }, 5);
                if (parts.Length == 5)
                {
                    int senderId = int.Parse(parts[1]);
                    string senderName = parts[2];
                    string message = parts[3];
                    string signature = parts[4];

                    if (senderId == _userId && senderName == _username)
                    {
                        bool isSignatureValid = Server.VerifyMessageSignature(message, signature, senderId);

                        if (isSignatureValid)
                        {
                            Server.WriteLog($"Mensagem assinada válida de {senderName}: {message}");
                            Server.BroadcastMessage(data, clientID);
                            byte[] ack = protocolSI.Make(ProtocolSICmdType.ACK);
                            networkStream.Write(ack, 0, ack.Length);
                        }
                        else
                        {
                            Server.WriteLog($"Assinatura inválida de {senderName}");
                            byte[] ack = protocolSI.Make(ProtocolSICmdType.ACK, "INVALID_SIGNATURE");
                            networkStream.Write(ack, 0, ack.Length);
                        }
                    }
                    else
                    {
                        Server.WriteLog($"Tentativa de falsificação detectada (cliente {clientID})");
                        byte[] ack = protocolSI.Make(ProtocolSICmdType.ACK, "AUTHENTICATION_ERROR");
                        networkStream.Write(ack, 0, ack.Length);
                    }
                }
            }
            catch
            {
                Server.WriteLog($"Erro ao processar mensagem assinada (cliente {clientID})");
                byte[] ack = protocolSI.Make(ProtocolSICmdType.ACK, "PROCESSING_ERROR");
                networkStream.Write(ack, 0, ack.Length);
            }
        }
    }
}