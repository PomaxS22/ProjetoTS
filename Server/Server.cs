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
using System.Threading.Tasks;

namespace Server
{
    class Server
    {
        private const int PORT = 10000;

        // Constantes para hash segura de palavras-passe
        private const int SALTSIZE = 8;
        private const int NUMBER_OF_ITERATIONS = 50000;

        // Sistema de registo
        private static readonly string LOG_FILE_PATH = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "server_secure_log.txt");
        private static readonly object logLock = new object();

        // Lista estática para armazenar os gestores de cliente
        public static readonly List<ClientHandler> connectedClients = new List<ClientHandler>();

        // NOVO: Armazenar chaves públicas RSA para validação de assinaturas
        private static readonly Dictionary<int, RSACryptoServiceProvider> userPublicKeys = new Dictionary<int, RSACryptoServiceProvider>();
        private static readonly object publicKeysLock = new object();

        /// <summary>
        /// Escreve entrada no registo com timestamp e categoria
        /// </summary>
        public static void WriteLog(string message, string category = "INFO")
        {
            try
            {
                lock (logLock)
                {
                    string timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss.fff");
                    string logEntry = $"[{timestamp}] [{category}] {message}";

                    // Escrever no ficheiro
                    File.AppendAllText(LOG_FILE_PATH, logEntry + Environment.NewLine);

                    // Também escrever na consola
                    Console.WriteLine(logEntry);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Erro ao escrever registo: {ex.Message}");
            }
        }

        /// <summary>
        /// Registo detalhado de dados processados (para depuração)
        /// </summary>
        public static void WriteDetailedLog(string operation, string details, string category = "DATA")
        {
            WriteLog($"{operation} - {details}", category);
        }

        /// <summary>
        /// Registo de erro com stack trace
        /// </summary>
        public static void WriteErrorLog(string message, Exception ex)
        {
            WriteLog($"ERRO: {message}", "ERROR");
            if (ex != null)
            {
                WriteLog($"Exception: {ex.Message}", "ERROR");
                WriteLog($"StackTrace: {ex.StackTrace}", "ERROR");

                if (ex.InnerException != null)
                {
                    WriteLog($"InnerException: {ex.InnerException.Message}", "ERROR");
                }
            }
        }

        /// <summary>
        /// Registo de segurança/criptografia
        /// </summary>
        public static void WriteSecurityLog(string operation, string details, int clientId = -1)
        {
            string clientInfo = clientId > 0 ? $"Cliente {clientId}" : "Sistema";
            WriteLog($"🔐 {clientInfo}: {operation} - {details}", "SECURITY");
        }

        /// <summary>
        /// NOVO: Registo específico para assinaturas digitais
        /// </summary>
        public static void WriteSignatureLog(string operation, string details, int userId = -1)
        {
            string userInfo = userId > 0 ? $"Utilizador {userId}" : "Sistema";
            WriteLog($"🔏 {userInfo}: {operation} - {details}", "SIGNATURE");
        }

        /// <summary>
        /// Gerar salt criptograficamente seguro
        /// </summary>
        public static byte[] GenerateSalt()
        {
            RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
            byte[] buff = new byte[SALTSIZE];
            rng.GetBytes(buff);
            WriteSecurityLog("Salt Generated", $"Salt de {SALTSIZE} bytes gerado");
            return buff;
        }

        /// <summary>
        /// Gerar hash salgada usando PBKDF2
        /// </summary>
        public static byte[] GenerateSaltedHash(string password, byte[] salt)
        {
            Rfc2898DeriveBytes rfc2898 = new Rfc2898DeriveBytes(password, salt, NUMBER_OF_ITERATIONS);
            byte[] hash = rfc2898.GetBytes(32); // hash de 256-bit
            WriteSecurityLog("Hash Generated", $"Hash PBKDF2 gerada com {NUMBER_OF_ITERATIONS} iterações, tamanho: {hash.Length * 8} bits");
            return hash;
        }

        /// <summary>
        /// Verificar palavra-passe contra hash e salt armazenadas
        /// </summary>
        public static bool VerifyPassword(string password, byte[] storedHash, byte[] storedSalt)
        {
            try
            {
                byte[] computedHash = GenerateSaltedHash(password, storedSalt);
                bool isValid = storedHash.SequenceEqual(computedHash);
                WriteSecurityLog("Password Verification", $"Resultado: {(isValid ? "SUCESSO" : "FALHADO")}");
                return isValid;
            }
            catch (Exception ex)
            {
                WriteErrorLog("Erro na verificação de palavra-passe", ex);
                return false;
            }
        }

        /// <summary>
        /// NOVO: Registar chave pública RSA de um utilizador para validação de assinaturas
        /// </summary>
        public static bool RegisterUserPublicKey(int userId, string publicKeyXml)
        {
            try
            {
                lock (publicKeysLock)
                {
                    // Remover chave anterior se existir
                    if (userPublicKeys.ContainsKey(userId))
                    {
                        userPublicKeys[userId].Dispose();
                        userPublicKeys.Remove(userId);
                    }

                    // Adicionar nova chave
                    RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
                    rsa.FromXmlString(publicKeyXml);
                    userPublicKeys[userId] = rsa;

                    WriteSignatureLog("Public Key Registered", $"Chave pública registada para validação de assinaturas", userId);
                    return true;
                }
            }
            catch (Exception ex)
            {
                WriteErrorLog($"Erro ao registar chave pública do utilizador {userId}", ex);
                return false;
            }
        }

        /// <summary>
        /// NOVO: Verificar assinatura digital de uma mensagem
        /// </summary>
        public static bool VerifyMessageSignature(string message, string signatureBase64, int senderId)
        {
            try
            {
                lock (publicKeysLock)
                {
                    if (!userPublicKeys.ContainsKey(senderId))
                    {
                        WriteSignatureLog("Verification Failed", $"Chave pública não encontrada para utilizador {senderId}", senderId);
                        return false;
                    }

                    RSACryptoServiceProvider senderPublicKey = userPublicKeys[senderId];
                    byte[] messageBytes = Encoding.UTF8.GetBytes(message);
                    byte[] signature = Convert.FromBase64String(signatureBase64);

                    // Verificar assinatura usando SHA256
                    bool isValid = senderPublicKey.VerifyData(messageBytes, new SHA256CryptoServiceProvider(), signature);

                    WriteSignatureLog("Signature Verification", $"Resultado: {(isValid ? "VÁLIDA" : "INVÁLIDA")}", senderId);
                    return isValid;
                }
            }
            catch (Exception ex)
            {
                WriteErrorLog($"Erro na verificação de assinatura do utilizador {senderId}", ex);
                return false;
            }
        }

        /// <summary>
        /// NOVO: Obter todas as chaves públicas para enviar aos clientes
        /// </summary>
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
                        string publicKeyXml = keyPair.Value.ToXmlString(false); // Apenas chave pública
                        keyEntries.Add($"{userId}:{publicKeyXml}");
                    }

                    string result = "PUBLIC_KEYS:" + string.Join("|", keyEntries);
                    WriteSignatureLog("Public Keys Distribution", $"Enviando {keyEntries.Count} chaves públicas");
                    return result;
                }
            }
            catch (Exception ex)
            {
                WriteErrorLog("Erro ao preparar chaves públicas para distribuição", ex);
                return "PUBLIC_KEYS:";
            }
        }

        // Método para adicionar cliente à lista
        public static void AddClient(ClientHandler client)
        {
            lock (connectedClients)
            {
                connectedClients.Add(client);
                WriteLog($"Cliente {client.ClientID} adicionado à lista. Total: {connectedClients.Count}", "CLIENT_MGR");
            }
        }

        // Método para remover cliente da lista
        public static void RemoveClient(ClientHandler client)
        {
            lock (connectedClients)
            {
                connectedClients.Remove(client);
                WriteLog($"Cliente {client.ClientID} removido da lista. Total: {connectedClients.Count}", "CLIENT_MGR");
            }
        }

        // NOVO: Método para enviar mensagem assinada a todos os clientes (apenas após validação)
        public static void BroadcastSignedMessage(string signedMessageData, int excludeClientId = -1)
        {
            lock (connectedClients)
            {
                WriteLog($"Broadcasting mensagem assinada para {connectedClients.Count} clientes (excepto {excludeClientId})", "BROADCAST_SIGNED");

                foreach (var client in connectedClients)
                {
                    if (client.ClientID != excludeClientId) // Não enviar para o remetente
                    {
                        client.SendMessage(signedMessageData);
                    }
                }
            }
        }

        // Método para enviar mensagem a todos os clientes (mantido para compatibilidade)
        public static void BroadcastMessage(string message, int excludeClientId = -1)
        {
            lock (connectedClients)
            {
                WriteLog($"Broadcasting para {connectedClients.Count} clientes (excepto {excludeClientId}): {message}", "BROADCAST");

                foreach (var client in connectedClients)
                {
                    if (client.ClientID != excludeClientId)
                    {
                        client.SendMessage(message);
                    }
                }
            }
        }

        /// <summary>
        /// NOVO: Enviar chaves públicas para um cliente específico
        /// </summary>
        public static void SendPublicKeysToClient(ClientHandler client)
        {
            try
            {
                string publicKeysData = GetAllPublicKeysForDistribution();
                client.SendMessage(publicKeysData);
                WriteSignatureLog("Public Keys Sent", $"Chaves públicas enviadas para cliente {client.ClientID}");
            }
            catch (Exception ex)
            {
                WriteErrorLog($"Erro ao enviar chaves públicas para cliente {client.ClientID}", ex);
            }
        }

        static void Main(string[] args)
        {
            try
            {
                WriteLog("=== INICIANDO SERVIDOR SEGURO COM ASSINATURAS DIGITAIS ===", "STARTUP");
                WriteLog("🔐🔏 Sistema de chat seguro com assinaturas digitais a iniciar...", "STARTUP");

                // Registo de informações do sistema
                WriteLog($"Versão .NET Framework: {Environment.Version}", "SYSTEM");
                WriteLog($"Directório actual: {AppDomain.CurrentDomain.BaseDirectory}", "SYSTEM");
                WriteLog($"Registo será guardado em: {LOG_FILE_PATH}", "SYSTEM");
                WriteSecurityLog("Sistema Iniciado", $"Configurações de segurança: SALTSIZE={SALTSIZE}, ITERATIONS={NUMBER_OF_ITERATIONS}");
                WriteSignatureLog("Sistema Iniciado", "Sistema de assinaturas digitais activado");

                // Configurar o directório de dados
                AppDomain.CurrentDomain.SetData("DataDirectory",
                    System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "App_Data"));

                // Criar o directório se não existir
                string dataDir = AppDomain.CurrentDomain.GetData("DataDirectory").ToString();
                if (!System.IO.Directory.Exists(dataDir))
                {
                    System.IO.Directory.CreateDirectory(dataDir);
                    WriteLog($"Directório App_Data criado em: {dataDir}", "SETUP");
                }
                else
                {
                    WriteLog($"Directório App_Data já existe: {dataDir}", "SETUP");
                }

                // Configurar a inicialização da base de dados
                Database.SetInitializer(new CreateDatabaseIfNotExists<ApplicationDbContext>());

                // Inicializar e garantir que a base de dados existe
                using (var dbContext = new ApplicationDbContext())
                {
                    WriteLog("A verificar/criar base de dados...", "DATABASE");
                    dbContext.Database.CreateIfNotExists();
                    WriteLog("Base de dados verificada com sucesso", "DATABASE");

                    // Verificar utilizadores existentes
                    int userCount = dbContext.Users.Count();
                    if (userCount == 0)
                    {
                        WriteLog("Nenhum utilizador encontrado. Base de dados vazia.", "DATABASE");
                    }
                    else
                    {
                        WriteLog($"Base de dados contém {userCount} utilizadores", "DATABASE");
                    }

                    IPEndPoint endpoint = new IPEndPoint(IPAddress.Any, PORT);
                    TcpListener listener = new TcpListener(endpoint);
                    WriteLog($"A iniciar listener na porta {PORT}", "NETWORK");
                    listener.Start();
                    WriteLog("🔐🔏 SERVIDOR SEGURO COM ASSINATURAS PRONTO - A aguardar ligações...", "STARTUP");

                    int clientCounter = 0;

                    while (true)
                    {
                        WriteLog("A aguardar ligação de cliente...", "NETWORK");
                        TcpClient client = listener.AcceptTcpClient();
                        clientCounter++;

                        string clientEndpoint = client.Client.RemoteEndPoint?.ToString() ?? "Desconhecido";
                        WriteLog($"Cliente {clientCounter} ligado de {clientEndpoint}", "CONNECTION");

                        ClientHandler clientHandler = new ClientHandler(client, clientCounter);
                        clientHandler.Handle();
                    }
                }
            }
            catch (Exception ex)
            {
                WriteErrorLog("ERRO CRÍTICO no servidor", ex);
            }
            finally
            {
                WriteLog("=== SERVIDOR SEGURO A ENCERRAR ===", "SHUTDOWN");

                // NOVO: Limpar chaves RSA
                lock (publicKeysLock)
                {
                    foreach (var keyPair in userPublicKeys)
                    {
                        keyPair.Value.Dispose();
                    }
                    userPublicKeys.Clear();
                    WriteSignatureLog("Sistema Encerrado", "Chaves RSA limpas da memória");
                }

                WriteLog("Prima qualquer tecla para sair...", "SHUTDOWN");
                Console.ReadKey();
            }
        }
    }

    class ClientHandler
    {
        private TcpClient client;
        private int clientID;
        private int _userId = -1; // ID do utilizador autenticado
        private string _username = null; // Nome do utilizador autenticado

        // Variáveis de encriptação simples
        private byte[] aesKey;
        private byte[] aesIV;
        private bool isEncryptionEstablished = false;

        // Propriedade pública para aceder ao ID do cliente
        public int ClientID { get { return clientID; } }

        public ClientHandler(TcpClient client, int clientID)
        {
            this.client = client;
            this.clientID = clientID;

            // Registo da criação do gestor
            Server.WriteLog($"ClientHandler criado para cliente {clientID}", "CLIENT_HANDLER");

            // Adicionar este cliente à lista de clientes ligados
            Server.AddClient(this);
        }

        // Método para enviar uma mensagem encriptada para este cliente específico
        public void SendMessage(string message)
        {
            try
            {
                NetworkStream ns = client.GetStream();
                ProtocolSI ps = new ProtocolSI();

                if (isEncryptionEstablished)
                {
                    // Enviar mensagem encriptada
                    string encryptedMessage = EncryptWithAES(message);
                    byte[] packet = ps.Make(ProtocolSICmdType.DATA, encryptedMessage);
                    ns.Write(packet, 0, packet.Length);
                    Server.WriteDetailedLog($"Mensagem encriptada enviada para cliente {clientID}", $"Tamanho: {packet.Length} bytes", "SEND_ENCRYPTED");
                }
                else
                {
                    // Enviar mensagem simples (para clientes não encriptados)
                    byte[] packet = ps.Make(ProtocolSICmdType.DATA, message);
                    ns.Write(packet, 0, packet.Length);
                    Server.WriteDetailedLog($"Mensagem simples enviada para cliente {clientID}", $"Conteúdo: {message}, Tamanho: {packet.Length} bytes", "SEND_PLAIN");
                }
            }
            catch (Exception ex)
            {
                Server.WriteErrorLog($"Erro ao enviar mensagem para cliente {clientID}", ex);
            }
        }

        /// <summary>
        /// Simples: Gerar chave e IV AES, encriptar com chave pública RSA do cliente
        /// </summary>
        private byte[] GenerateAndEncryptAESKey(string clientPublicKeyXml)
        {
            try
            {
                Server.WriteSecurityLog("Key Generation Started", "A gerar chave AES para troca segura", clientID);

                // Gerar chave e IV AES
                using (AesCryptoServiceProvider aes = new AesCryptoServiceProvider())
                {
                    aes.KeySize = 256; // chave de 256-bit
                    aes.GenerateKey();
                    aes.GenerateIV();

                    // Armazenar para este cliente
                    aesKey = new byte[aes.Key.Length];
                    aesIV = new byte[aes.IV.Length];
                    Array.Copy(aes.Key, aesKey, aes.Key.Length);
                    Array.Copy(aes.IV, aesIV, aes.IV.Length);

                    Server.WriteSecurityLog("AES Key Generated", $"Chave: {aesKey.Length * 8} bits, IV: {aesIV.Length * 8} bits", clientID);

                    // Combinar chave + IV para encriptação
                    byte[] combined = new byte[aesKey.Length + aesIV.Length];
                    Array.Copy(aesKey, 0, combined, 0, aesKey.Length);
                    Array.Copy(aesIV, 0, combined, aesKey.Length, aesIV.Length);

                    // Encriptar com chave pública RSA do cliente
                    using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
                    {
                        rsa.FromXmlString(clientPublicKeyXml);
                        byte[] encryptedKey = rsa.Encrypt(combined, false);
                        Server.WriteSecurityLog("RSA Encryption Completed", $"Chave AES encriptada com RSA, tamanho: {encryptedKey.Length} bytes", clientID);
                        return encryptedKey;
                    }
                }
            }
            catch (Exception ex)
            {
                Server.WriteErrorLog($"Falha ao gerar chave AES encriptada para cliente {clientID}", ex);
                throw new Exception($"Falhou ao gerar chave AES encriptada: {ex.Message}");
            }
        }

        /// <summary>
        /// Encriptação AES simples
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
                    string encrypted = Convert.ToBase64String(encryptedBytes);

                    Server.WriteDetailedLog($"Texto encriptado para cliente {clientID}", $"Original: {plainBytes.Length} bytes → Encriptado: {encryptedBytes.Length} bytes", "ENCRYPT");
                    return encrypted;
                }
            }
            catch (Exception ex)
            {
                Server.WriteErrorLog($"Falha na encriptação para cliente {clientID}", ex);
                throw new Exception($"Encriptação falhou: {ex.Message}");
            }
        }

        /// <summary>
        /// Desencriptação AES simples
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
                    string decrypted = Encoding.UTF8.GetString(decryptedBytes);

                    Server.WriteDetailedLog($"Texto desencriptado do cliente {clientID}", $"Encriptado: {encryptedBytes.Length} bytes → Original: {decryptedBytes.Length} bytes", "DECRYPT");
                    return decrypted;
                }
            }
            catch (Exception ex)
            {
                Server.WriteErrorLog($"Falha na desencriptação do cliente {clientID}", ex);
                throw new Exception($"Desencriptação falhou: {ex.Message}");
            }
        }

        /// <summary>
        /// Verificar palavra-passe do utilizador usando comparação de hash segura
        /// </summary>
        private bool VerifyUserPassword(User user, string inputPassword)
        {
            try
            {
                Server.WriteLog($"A verificar palavra-passe para utilizador {user.Username}", "AUTH_VERIFY");

                // Formato da palavra-passe: "hashBase64:saltBase64"
                string[] passwordParts = user.Password.Split(':');
                if (passwordParts.Length == 2)
                {
                    // Novo formato seguro: hash:salt (ambos codificados em Base64)
                    byte[] storedHash = Convert.FromBase64String(passwordParts[0]);
                    byte[] storedSalt = Convert.FromBase64String(passwordParts[1]);

                    Server.WriteSecurityLog("Password Verification", $"A verificar palavra-passe segura para {user.Username}", clientID);

                    // Usar método de verificação
                    bool result = Server.VerifyPassword(inputPassword, storedHash, storedSalt);
                    Server.WriteLog($"Resultado da verificação para {user.Username}: {(result ? "SUCESSO" : "FALHADO")}", "AUTH_RESULT");
                    return result;
                }
                else
                {
                    // Formato antigo de texto simples (para compatibilidade)
                    Server.WriteLog($"⚠️ Utilizador {user.Username} tem palavra-passe em texto simples - deve ser migrado", "AUTH_WARNING");
                    bool result = user.Password == inputPassword;
                    Server.WriteLog($"Verificação de palavra-passe simples para {user.Username}: {(result ? "SUCESSO" : "FALHADO")}", "AUTH_RESULT");
                    return result;
                }
            }
            catch (Exception ex)
            {
                Server.WriteErrorLog($"Erro ao verificar palavra-passe para {user.Username}", ex);
                return false;
            }
        }

        public void Handle()
        {
            Thread thread = new Thread(threadHandler);
            thread.Start();
            Server.WriteLog($"Thread iniciada para cliente {clientID}", "THREAD");
        }

        private void threadHandler()
        {
            try
            {
                NetworkStream networkStream = this.client.GetStream();
                ProtocolSI protocolSI = new ProtocolSI();

                Server.WriteLog($"Gestor iniciado para cliente {clientID}", "CLIENT_HANDLER");

                while (protocolSI.GetCmdType() != ProtocolSICmdType.EOT)
                {
                    int bytesRead = networkStream.Read(protocolSI.Buffer, 0, protocolSI.Buffer.Length);
                    byte[] ack;

                    // Registo dos dados recebidos
                    Server.WriteDetailedLog($"Dados recebidos do cliente {clientID}", $"Bytes: {bytesRead}, Comando: {protocolSI.GetCmdType()}", "RECEIVE");

                    switch (protocolSI.GetCmdType())
                    {
                        case ProtocolSICmdType.DATA: // Mensagens, Troca de Chaves e Assinaturas
                            string rawData = protocolSI.GetStringFromData();

                            if (rawData.StartsWith("KEY_EXCHANGE:"))
                            {
                                // Isto é um pedido de troca de chaves
                                string clientPublicKeyXml = rawData.Substring("KEY_EXCHANGE:".Length);
                                Server.WriteSecurityLog("Key Exchange Request", "Cliente enviou chave pública RSA", clientID);

                                try
                                {
                                    // Gerar chave AES e encriptar com chave pública RSA do cliente
                                    byte[] encryptedAESKey = GenerateAndEncryptAESKey(clientPublicKeyXml);
                                    string encryptedKeyBase64 = Convert.ToBase64String(encryptedAESKey);

                                    // Enviar chave AES encriptada de volta ao cliente
                                    ack = protocolSI.Make(ProtocolSICmdType.ACK, encryptedKeyBase64);
                                    networkStream.Write(ack, 0, ack.Length);

                                    isEncryptionEstablished = true;
                                    Server.WriteSecurityLog("Encryption Established", "Criptografia AES estabelecida com sucesso", clientID);
                                }
                                catch (Exception ex)
                                {
                                    Server.WriteErrorLog($"Erro ao estabelecer criptografia com cliente {clientID}", ex);
                                    ack = protocolSI.Make(ProtocolSICmdType.ACK, "ERROR");
                                    networkStream.Write(ack, 0, ack.Length);
                                }
                            }
                            else
                            {
                                // Isto pode ser uma mensagem regular ou comando especial
                                try
                                {
                                    string decryptedData;
                                    if (isEncryptionEstablished)
                                    {
                                        // Desencriptar dados
                                        decryptedData = DecryptWithAES(rawData);
                                        Server.WriteDetailedLog($"Dados encriptados recebidos do cliente {clientID}", $"Conteúdo: {decryptedData}", "DATA_ENCRYPTED");
                                    }
                                    else
                                    {
                                        // Dados simples
                                        decryptedData = rawData;
                                        Server.WriteDetailedLog($"Dados simples recebidos do cliente {clientID}", $"Conteúdo: {decryptedData}", "DATA_PLAIN");
                                    }

                                    // NOVO: Processar comandos especiais para assinaturas
                                    if (decryptedData.StartsWith("REGISTER_SIGNATURE_KEY:"))
                                    {
                                        // Comando para registar chave pública para assinaturas
                                        ProcessSignatureKeyRegistration(decryptedData, networkStream, protocolSI);
                                    }
                                    else if (decryptedData.StartsWith("REQUEST_PUBLIC_KEYS"))
                                    {
                                        // Comando para solicitar chaves públicas de outros utilizadores
                                        ProcessPublicKeysRequest(networkStream, protocolSI);
                                    }
                                    else if (decryptedData.StartsWith("SIGNED_MESSAGE:"))
                                    {
                                        // Mensagem assinada digitalmente
                                        ProcessSignedMessage(decryptedData, networkStream, protocolSI);
                                    }
                                    else
                                    {
                                        // Mensagem regular (compatibilidade)
                                        string formattedMessage;
                                        if (_userId > 0 && _username != null)
                                        {
                                            formattedMessage = $"{_username}: {decryptedData}";
                                            Server.WriteLog($"Mensagem do utilizador {_username} (ID: {_userId}): {decryptedData}", "USER_MESSAGE");
                                        }
                                        else
                                        {
                                            formattedMessage = $"Cliente {clientID}: {decryptedData}";
                                            Server.WriteLog($"Mensagem do cliente anónimo {clientID}: {decryptedData}", "ANON_MESSAGE");
                                        }

                                        // Enviar para todos os outros clientes (modo compatibilidade)
                                        Server.BroadcastMessage(formattedMessage, clientID);

                                        ack = protocolSI.Make(ProtocolSICmdType.ACK);
                                        networkStream.Write(ack, 0, ack.Length);
                                        Server.WriteDetailedLog($"ACK enviado para cliente {clientID}", "Resposta a mensagem", "PROTOCOL");
                                    }
                                }
                                catch (Exception ex)
                                {
                                    Server.WriteErrorLog($"Erro ao processar dados do cliente {clientID}", ex);
                                    ack = protocolSI.Make(ProtocolSICmdType.ACK);
                                    networkStream.Write(ack, 0, ack.Length);
                                }
                            }
                            break;

                        case ProtocolSICmdType.USER_OPTION_1: // Login Encriptado
                            try
                            {
                                string authData;
                                if (isEncryptionEstablished)
                                {
                                    // Desencriptar dados de login
                                    string encryptedAuthData = protocolSI.GetStringFromData();
                                    authData = DecryptWithAES(encryptedAuthData);
                                    Server.WriteLog($"Dados de login encriptados recebidos do cliente {clientID}", "LOGIN_ENCRYPTED");
                                }
                                else
                                {
                                    // Dados de login simples (compatibilidade)
                                    authData = protocolSI.GetStringFromData();
                                    Server.WriteLog($"Dados de login simples recebidos do cliente {clientID}", "LOGIN_PLAIN");
                                }

                                string[] credentials = authData.Split(':');

                                if (credentials.Length == 2)
                                {
                                    string username = credentials[0];
                                    string password = credentials[1];

                                    Server.WriteLog($"Tentativa de login: Utilizador: {username}, Cliente: {clientID}", "LOGIN_ATTEMPT");

                                    // Verificar credenciais na base de dados 
                                    using (var dbContext = new ApplicationDbContext())
                                    {
                                        var user = dbContext.Users.FirstOrDefault(u => u.Username == username);

                                        if (user != null && VerifyUserPassword(user, password))
                                        {
                                            // Login bem-sucedido
                                            Server.WriteLog($"Login bem-sucedido para Utilizador: {username}, Cliente: {clientID}", "LOGIN_SUCCESS");
                                            _userId = user.Id;
                                            _username = user.Username;

                                            // Preparar dados de resposta
                                            string responseData = $"{user.Id}:{user.Username}";

                                            if (isEncryptionEstablished)
                                            {
                                                // Enviar resposta encriptada
                                                string encryptedResponse = EncryptWithAES(responseData);
                                                byte[] response = protocolSI.Make(ProtocolSICmdType.USER_OPTION_2, encryptedResponse);
                                                networkStream.Write(response, 0, response.Length);
                                                Server.WriteLog($"Resposta de login encriptada enviada para {username}", "LOGIN_RESPONSE");
                                            }
                                            else
                                            {
                                                // Enviar resposta simples
                                                byte[] response = protocolSI.Make(ProtocolSICmdType.USER_OPTION_2, responseData);
                                                networkStream.Write(response, 0, response.Length);
                                                Server.WriteLog($"Resposta de login simples enviada para {username}", "LOGIN_RESPONSE");
                                            }

                                            // Avisar outros clientes que este utilizador entrou
                                            Server.BroadcastMessage($"🔐🔏 !!! {username} entrou no chat seguro com assinaturas !!!", clientID);
                                        }
                                        else
                                        {
                                            // Login falhou
                                            Server.WriteLog($"Login falhou para Utilizador: {username}, Cliente: {clientID}", "LOGIN_FAILED");

                                            // Enviar resposta de falha
                                            byte[] response = protocolSI.Make(ProtocolSICmdType.ACK);
                                            networkStream.Write(response, 0, response.Length);
                                        }
                                    }
                                }
                                else
                                {
                                    // Formato inválido
                                    Server.WriteLog($"Formato de dados de autenticação inválido do cliente {clientID}", "AUTH_ERROR");
                                    byte[] response = protocolSI.Make(ProtocolSICmdType.ACK);
                                    networkStream.Write(response, 0, response.Length);
                                }
                            }
                            catch (Exception ex)
                            {
                                Server.WriteErrorLog($"Erro ao processar login do cliente {clientID}", ex);
                                byte[] response = protocolSI.Make(ProtocolSICmdType.ACK);
                                networkStream.Write(response, 0, response.Length);
                            }
                            break;

                        case ProtocolSICmdType.USER_OPTION_3: // Registo Encriptado
                            try
                            {
                                string regData;
                                if (isEncryptionEstablished)
                                {
                                    // Desencriptar dados de registo
                                    string encryptedRegData = protocolSI.GetStringFromData();
                                    regData = DecryptWithAES(encryptedRegData);
                                    Server.WriteLog($"Dados de registo encriptados recebidos do cliente {clientID}", "REGISTER_ENCRYPTED");
                                }
                                else
                                {
                                    // Dados de registo simples (compatibilidade)
                                    regData = protocolSI.GetStringFromData();
                                    Server.WriteLog($"Dados de registo simples recebidos do cliente {clientID}", "REGISTER_PLAIN");
                                }

                                string[] regCredentials = regData.Split(':');

                                if (regCredentials.Length == 2)
                                {
                                    string regUsername = regCredentials[0];
                                    string regPassword = regCredentials[1];

                                    Server.WriteLog($"Tentativa de registo: Utilizador: {regUsername}, Cliente: {clientID}", "REGISTER_ATTEMPT");

                                    // Verificar se o utilizador já existe e criar novo se não existir
                                    using (var dbContext = new ApplicationDbContext())
                                    {
                                        // Verificar se o nome de utilizador já existe
                                        var existingUser = dbContext.Users
                                            .FirstOrDefault(u => u.Username == regUsername);

                                        string responseMessage;
                                        if (existingUser == null)
                                        {
                                            try
                                            {
                                                // Nome de utilizador não existe, criar novo utilizador com palavra-passe segura
                                                byte[] salt = Server.GenerateSalt();
                                                byte[] hash = Server.GenerateSaltedHash(regPassword, salt);

                                                // Armazenar como strings Base64 (formato: hash:salt)
                                                string hashBase64 = Convert.ToBase64String(hash);
                                                string saltBase64 = Convert.ToBase64String(salt);

                                                var newUser = new User
                                                {
                                                    Username = regUsername,
                                                    Password = $"{hashBase64}:{saltBase64}"
                                                };

                                                dbContext.Users.Add(newUser);
                                                dbContext.SaveChanges();

                                                Server.WriteLog($"Utilizador {regUsername} registado com sucesso (PBKDF2)", "REGISTER_SUCCESS");
                                                responseMessage = "SUCCESS";
                                            }
                                            catch (Exception ex)
                                            {
                                                Server.WriteErrorLog($"Erro ao guardar utilizador {regUsername}", ex);
                                                responseMessage = "FAILURE";
                                            }
                                        }
                                        else
                                        {
                                            // Nome de utilizador já existe
                                            Server.WriteLog($"Registo falhou: Nome de utilizador {regUsername} já existe", "REGISTER_FAILED");
                                            responseMessage = "FAILURE";
                                        }

                                        // Enviar resposta (encriptada ou simples)
                                        if (isEncryptionEstablished)
                                        {
                                            string encryptedResponse = EncryptWithAES(responseMessage);
                                            byte[] response = protocolSI.Make(ProtocolSICmdType.USER_OPTION_4, encryptedResponse);
                                            networkStream.Write(response, 0, response.Length);
                                            Server.WriteLog($"Resposta de registo encriptada enviada: {responseMessage}", "REGISTER_RESPONSE");
                                        }
                                        else
                                        {
                                            byte[] response = protocolSI.Make(ProtocolSICmdType.USER_OPTION_4, responseMessage);
                                            networkStream.Write(response, 0, response.Length);
                                            Server.WriteLog($"Resposta de registo simples enviada: {responseMessage}", "REGISTER_RESPONSE");
                                        }
                                    }
                                }
                                else
                                {
                                    // Formato inválido
                                    Server.WriteLog($"Formato de dados de registo inválido do cliente {clientID}", "REGISTER_ERROR");
                                    string errorMsg = "FAILURE";

                                    if (isEncryptionEstablished)
                                    {
                                        string encryptedError = EncryptWithAES(errorMsg);
                                        byte[] response = protocolSI.Make(ProtocolSICmdType.USER_OPTION_4, encryptedError);
                                        networkStream.Write(response, 0, response.Length);
                                    }
                                    else
                                    {
                                        byte[] response = protocolSI.Make(ProtocolSICmdType.USER_OPTION_4, errorMsg);
                                        networkStream.Write(response, 0, response.Length);
                                    }
                                }
                            }
                            catch (Exception ex)
                            {
                                Server.WriteErrorLog($"Erro ao processar registo do cliente {clientID}", ex);
                                string errorMsg = "FAILURE";

                                if (isEncryptionEstablished)
                                {
                                    string encryptedError = EncryptWithAES(errorMsg);
                                    byte[] response = protocolSI.Make(ProtocolSICmdType.USER_OPTION_4, encryptedError);
                                    networkStream.Write(response, 0, response.Length);
                                }
                                else
                                {
                                    byte[] response = protocolSI.Make(ProtocolSICmdType.USER_OPTION_4, errorMsg);
                                    networkStream.Write(response, 0, response.Length);
                                }
                            }
                            break;

                        case ProtocolSICmdType.EOT:
                            Server.WriteLog($"Cliente {clientID} enviou comando de encerramento", "DISCONNECT");
                            ack = protocolSI.Make(ProtocolSICmdType.ACK);
                            networkStream.Write(ack, 0, ack.Length);
                            Server.WriteLog($"ACK de encerramento enviado para cliente {clientID}", "DISCONNECT");
                            break;

                        default:
                            Server.WriteLog($"Comando desconhecido do cliente {clientID}: {protocolSI.GetCmdType()}", "PROTOCOL_ERROR");
                            break;
                    }
                }
            }
            catch (Exception ex)
            {
                Server.WriteErrorLog($"Erro no gestor do cliente {clientID}", ex);
            }
            finally
            {
                // Registo da desligação
                if (_userId > 0 && _username != null)
                {
                    Server.WriteLog($"Utilizador {_username} (ID: {_userId}) desligou - Cliente {clientID}", "USER_DISCONNECT");
                }
                else
                {
                    Server.WriteLog($"Cliente anónimo {clientID} desligou", "CLIENT_DISCONNECT");
                }

                // Remover este cliente da lista ao desligar
                Server.RemoveClient(this);

                // Notificar outros utilizadores que este saiu (se estava autenticado)
                if (_userId > 0 && _username != null)
                {
                    Server.BroadcastMessage($"🔐🔏 *** {_username} saiu do chat seguro ***");
                }

                try
                {
                    client.Close();
                    Server.WriteLog($"Ligação fechada para cliente {clientID}", "CONNECTION");
                }
                catch (Exception ex)
                {
                    Server.WriteErrorLog($"Erro ao fechar ligação do cliente {clientID}", ex);
                }
            }
        }

        /// <summary>
        /// NOVO: Processar registo de chave pública para assinaturas
        /// </summary>
        private void ProcessSignatureKeyRegistration(string data, NetworkStream networkStream, ProtocolSI protocolSI)
        {
            try
            {
                // Formato: REGISTER_SIGNATURE_KEY:userId:publicKeyXml
                string[] parts = data.Split(new char[] { ':' }, 3);
                if (parts.Length == 3)
                {
                    int userId = int.Parse(parts[1]);
                    string publicKeyXml = parts[2];

                    // Verificar se é o utilizador correcto
                    if (userId == _userId)
                    {
                        bool success = Server.RegisterUserPublicKey(userId, publicKeyXml);
                        string responseMessage = success ? "SIGNATURE_KEY_REGISTERED" : "SIGNATURE_KEY_ERROR";

                        // Enviar resposta encriptada
                        string encryptedResponse = EncryptWithAES(responseMessage);
                        byte[] response = protocolSI.Make(ProtocolSICmdType.ACK, encryptedResponse);
                        networkStream.Write(response, 0, response.Length);

                        if (success)
                        {
                            Server.WriteSignatureLog("Key Registration Success", $"Chave pública registada para utilizador {_username}", _userId);

                            // Notificar outros clientes sobre nova chave disponível
                            Task.Run(() =>
                            {
                                Thread.Sleep(500); // Pequena pausa
                                BroadcastUpdatedPublicKeys();
                            });
                        }
                    }
                    else
                    {
                        Server.WriteSignatureLog("Key Registration Failed", $"Tentativa de registar chave para utilizador incorrecto", _userId);
                        string encryptedError = EncryptWithAES("SIGNATURE_KEY_ERROR");
                        byte[] response = protocolSI.Make(ProtocolSICmdType.ACK, encryptedError);
                        networkStream.Write(response, 0, response.Length);
                    }
                }
            }
            catch (Exception ex)
            {
                Server.WriteErrorLog($"Erro ao processar registo de chave para assinaturas do cliente {clientID}", ex);
                string encryptedError = EncryptWithAES("SIGNATURE_KEY_ERROR");
                byte[] response = protocolSI.Make(ProtocolSICmdType.ACK, encryptedError);
                networkStream.Write(response, 0, response.Length);
            }
        }

        /// <summary>
        /// NOVO: Processar pedido de chaves públicas
        /// </summary>
        private void ProcessPublicKeysRequest(NetworkStream networkStream, ProtocolSI protocolSI)
        {
            try
            {
                // Enviar todas as chaves públicas disponíveis
                Server.SendPublicKeysToClient(this);

                // Enviar ACK
                byte[] ack = protocolSI.Make(ProtocolSICmdType.ACK);
                networkStream.Write(ack, 0, ack.Length);

                Server.WriteSignatureLog("Public Keys Sent", $"Chaves públicas enviadas para cliente {clientID}");
            }
            catch (Exception ex)
            {
                Server.WriteErrorLog($"Erro ao processar pedido de chaves públicas do cliente {clientID}", ex);
                byte[] ack = protocolSI.Make(ProtocolSICmdType.ACK);
                networkStream.Write(ack, 0, ack.Length);
            }
        }

        /// <summary>
        /// NOVO: Processar mensagem assinada digitalmente
        /// </summary>
        private void ProcessSignedMessage(string data, NetworkStream networkStream, ProtocolSI protocolSI)
        {
            try
            {
                // Formato: SIGNED_MESSAGE:senderId:senderName:message:signature
                string[] parts = data.Split(new char[] { ':' }, 5);
                if (parts.Length == 5)
                {
                    int senderId = int.Parse(parts[1]);
                    string senderName = parts[2];
                    string message = parts[3];
                    string signature = parts[4];

                    // Verificar se é o utilizador correcto
                    if (senderId == _userId && senderName == _username)
                    {
                        // Verificar assinatura digital
                        bool isSignatureValid = Server.VerifyMessageSignature(message, signature, senderId);

                        if (isSignatureValid)
                        {
                            // Assinatura válida - fazer broadcast da mensagem
                            Server.BroadcastSignedMessage(data, clientID);
                            Server.WriteSignatureLog("Message Broadcast", $"Mensagem assinada válida enviada por {senderName}: {message}", senderId);

                            // Enviar ACK de sucesso
                            byte[] ack = protocolSI.Make(ProtocolSICmdType.ACK);
                            networkStream.Write(ack, 0, ack.Length);
                        }
                        else
                        {
                            // Assinatura inválida - rejeitar mensagem
                            Server.WriteSignatureLog("Message Rejected", $"Assinatura inválida de {senderName} - mensagem rejeitada", senderId);

                            // Enviar ACK com erro
                            byte[] ack = protocolSI.Make(ProtocolSICmdType.ACK, "INVALID_SIGNATURE");
                            networkStream.Write(ack, 0, ack.Length);
                        }
                    }
                    else
                    {
                        // Tentativa de falsificação
                        Server.WriteSignatureLog("Forgery Attempt", $"Tentativa de falsificação detectada - Cliente {clientID} tentou enviar como {senderName} (ID: {senderId})", _userId);

                        // Enviar ACK com erro
                        byte[] ack = protocolSI.Make(ProtocolSICmdType.ACK, "AUTHENTICATION_ERROR");
                        networkStream.Write(ack, 0, ack.Length);
                    }
                }
                else
                {
                    Server.WriteSignatureLog("Invalid Format", $"Formato de mensagem assinada inválido do cliente {clientID}");
                    byte[] ack = protocolSI.Make(ProtocolSICmdType.ACK, "INVALID_FORMAT");
                    networkStream.Write(ack, 0, ack.Length);
                }
            }
            catch (Exception ex)
            {
                Server.WriteErrorLog($"Erro ao processar mensagem assinada do cliente {clientID}", ex);
                byte[] ack = protocolSI.Make(ProtocolSICmdType.ACK, "PROCESSING_ERROR");
                networkStream.Write(ack, 0, ack.Length);
            }
        }

        /// <summary>
        /// NOVO: Fazer broadcast das chaves públicas actualizadas para todos os clientes
        /// </summary>
        public void BroadcastUpdatedPublicKeys()
        {
            try
            {
                lock (Server.connectedClients)
                {
                    foreach (var client in Server.connectedClients)
                    {
                        Server.SendPublicKeysToClient(client);
                    }
                }
                Server.WriteSignatureLog("Public Keys Broadcast", "Chaves públicas actualizadas enviadas para todos os clientes");
            }
            catch (Exception ex)
            {
                Server.WriteErrorLog("Erro ao fazer broadcast de chaves públicas actualizadas", ex);
            }
        }
    }
}