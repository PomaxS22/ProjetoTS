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

        // Teacher's constants for secure password hashing
        private const int SALTSIZE = 8;
        private const int NUMBER_OF_ITERATIONS = 50000;

        // Sistema de Logging
        private static readonly string LOG_FILE_PATH = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "server_secure_log.txt");
        private static readonly object logLock = new object();

        // Lista estática para armazenar os handlers de cliente
        private static readonly List<ClientHandler> connectedClients = new List<ClientHandler>();

        /// <summary>
        /// Escreve entrada no log com timestamp e categoria
        /// </summary>
        public static void WriteLog(string message, string category = "INFO")
        {
            try
            {
                lock (logLock)
                {
                    string timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss.fff");
                    string logEntry = $"[{timestamp}] [{category}] {message}";

                    // Escrever no arquivo
                    File.AppendAllText(LOG_FILE_PATH, logEntry + Environment.NewLine);

                    // Também escrever no console
                    Console.WriteLine(logEntry);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Erro ao escrever log: {ex.Message}");
            }
        }

        /// <summary>
        /// Log detalhado de dados processados (para debugging)
        /// </summary>
        public static void WriteDetailedLog(string operation, string details, string category = "DATA")
        {
            WriteLog($"{operation} - {details}", category);
        }

        /// <summary>
        /// Log de erro com stack trace
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
        /// Log de segurança/criptografia
        /// </summary>
        public static void WriteSecurityLog(string operation, string details, int clientId = -1)
        {
            string clientInfo = clientId > 0 ? $"Cliente {clientId}" : "Sistema";
            WriteLog($"🔐 {clientInfo}: {operation} - {details}", "SECURITY");
        }

        /// <summary>
        /// TEACHER'S METHOD: Generate cryptographically secure salt
        /// </summary>
        public static byte[] GenerateSalt()
        {
            //Generate a cryptographic random number.
            RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
            byte[] buff = new byte[SALTSIZE];
            rng.GetBytes(buff);
            WriteSecurityLog("Salt Generated", $"Salt de {SALTSIZE} bytes gerado");
            return buff;
        }

        /// <summary>
        /// TEACHER'S METHOD: Generate salted hash using PBKDF2
        /// </summary>
        public static byte[] GenerateSaltedHash(string password, byte[] salt)
        {
            Rfc2898DeriveBytes rfc2898 = new Rfc2898DeriveBytes(password, salt, NUMBER_OF_ITERATIONS);
            byte[] hash = rfc2898.GetBytes(32); // 256-bit hash
            WriteSecurityLog("Hash Generated", $"Hash PBKDF2 gerado com {NUMBER_OF_ITERATIONS} iterações, tamanho: {hash.Length * 8} bits");
            return hash;
        }

        /// <summary>
        /// TEACHER'S METHOD: Verify password against stored hash and salt
        /// </summary>
        public static bool VerifyPassword(string password, byte[] storedHash, byte[] storedSalt)
        {
            try
            {
                byte[] computedHash = GenerateSaltedHash(password, storedSalt);
                bool isValid = storedHash.SequenceEqual(computedHash);
                WriteSecurityLog("Password Verification", $"Resultado: {(isValid ? "SUCCESS" : "FAILED")}");
                return isValid;
            }
            catch (Exception ex)
            {
                WriteErrorLog("Erro na verificação de senha", ex);
                return false;
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

        // Método para enviar mensagem a todos os clientes
        public static void BroadcastMessage(string message, int excludeClientId = -1)
        {
            lock (connectedClients)
            {
                WriteLog($"Broadcasting para {connectedClients.Count} clientes (exceto {excludeClientId}): {message}", "BROADCAST");

                foreach (var client in connectedClients)
                {
                    if (client.ClientID != excludeClientId) // Não enviar para o remetente
                    {
                        client.SendMessage(message);
                    }
                }
            }
        }

        static void Main(string[] args)
        {
            try
            {
                WriteLog("=== INICIANDO SERVIDOR SEGURO ===", "STARTUP");
                WriteLog("🔐 Sistema de chat seguro com logging iniciando...", "STARTUP");

                // Log de informações do sistema
                WriteLog($"Versão .NET Framework: {Environment.Version}", "SYSTEM");
                WriteLog($"Diretório atual: {AppDomain.CurrentDomain.BaseDirectory}", "SYSTEM");
                WriteLog($"Log será salvo em: {LOG_FILE_PATH}", "SYSTEM");
                WriteSecurityLog("Sistema Iniciado", $"Configurações de segurança: SALTSIZE={SALTSIZE}, ITERATIONS={NUMBER_OF_ITERATIONS}");

                // Configurar o diretório de dados
                AppDomain.CurrentDomain.SetData("DataDirectory",
                    System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "App_Data"));

                // Criar o diretório se não existir
                string dataDir = AppDomain.CurrentDomain.GetData("DataDirectory").ToString();
                if (!System.IO.Directory.Exists(dataDir))
                {
                    System.IO.Directory.CreateDirectory(dataDir);
                    WriteLog($"Diretório App_Data criado em: {dataDir}", "SETUP");
                }
                else
                {
                    WriteLog($"Diretório App_Data já existe: {dataDir}", "SETUP");
                }

                // Configurar a inicialização do base de dados
                Database.SetInitializer(new CreateDatabaseIfNotExists<ApplicationDbContext>());

                // Inicializar e garantir que o base de dados existe
                using (var dbContext = new ApplicationDbContext())
                {
                    WriteLog("Verificando/criando base de dados...", "DATABASE");
                    dbContext.Database.CreateIfNotExists();
                    WriteLog("Base de dados verificada com sucesso", "DATABASE");

                    // Verificar users existentes
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
                    WriteLog($"Iniciando listener na porta {PORT}", "NETWORK");
                    listener.Start();
                    WriteLog("🔐 SERVIDOR SEGURO PRONTO - Aguardando conexões...", "STARTUP");

                    int clientCounter = 0;

                    while (true)
                    {
                        WriteLog("Aguardando conexão de cliente...", "NETWORK");
                        TcpClient client = listener.AcceptTcpClient();
                        clientCounter++;

                        string clientEndpoint = client.Client.RemoteEndPoint?.ToString() ?? "Unknown";
                        WriteLog($"Cliente {clientCounter} conectado de {clientEndpoint}", "CONNECTION");

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
                WriteLog("=== SERVIDOR SEGURO ENCERRANDO ===", "SHUTDOWN");
                WriteLog("Pressione qualquer tecla para sair...", "SHUTDOWN");
                Console.ReadKey();
            }
        }

        /// <summary>
        /// Create secure user using teacher's PBKDF2 method
        /// </summary>
        private static void CreateSecureUser(ApplicationDbContext dbContext, string username, string password)
        {
            WriteLog($"Criando usuário seguro: {username}", "USER_CREATION");

            byte[] salt = GenerateSalt();
            byte[] hash = GenerateSaltedHash(password, salt);

            // Store as Base64 strings temporarily (until User model is updated to byte[])
            string hashBase64 = Convert.ToBase64String(hash);
            string saltBase64 = Convert.ToBase64String(salt);

            dbContext.Users.Add(new User
            {
                Username = username,
                Password = $"{hashBase64}:{saltBase64}" // Format: hash:salt
            });

            WriteSecurityLog("User Created", $"Usuario {username} criado com hash seguro ({hash.Length * 8} bits)");
        }
    }

    class ClientHandler
    {
        private TcpClient client;
        private int clientID;
        private int _userId = -1; // ID do user logado
        private string _username = null; // Nome do user logado

        // Simple encryption variables
        private byte[] aesKey;
        private byte[] aesIV;
        private bool isEncryptionEstablished = false;

        // Propriedade pública para acessar o ID do cliente
        public int ClientID { get { return clientID; } }

        public ClientHandler(TcpClient client, int clientID)
        {
            this.client = client;
            this.clientID = clientID;

            // Log da criação do handler
            Server.WriteLog($"ClientHandler criado para cliente {clientID}", "CLIENT_HANDLER");

            // Adicionar este cliente à lista de clientes conectados
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
                    // Send encrypted message
                    string encryptedMessage = EncryptWithAES(message);
                    byte[] packet = ps.Make(ProtocolSICmdType.DATA, encryptedMessage);
                    ns.Write(packet, 0, packet.Length);
                    Server.WriteDetailedLog($"Mensagem encriptada enviada para cliente {clientID}", $"Tamanho: {packet.Length} bytes", "SEND_ENCRYPTED");
                }
                else
                {
                    // Send plain message (for non-encrypted clients)
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
        /// Simple: Generate AES key and IV, encrypt with client's RSA public key
        /// </summary>
        private byte[] GenerateAndEncryptAESKey(string clientPublicKeyXml)
        {
            try
            {
                Server.WriteSecurityLog("Key Generation Started", "Gerando chave AES para troca segura", clientID);

                // Generate AES key and IV
                using (AesCryptoServiceProvider aes = new AesCryptoServiceProvider())
                {
                    aes.KeySize = 256; // 256-bit key
                    aes.GenerateKey();
                    aes.GenerateIV();

                    // Store for this client
                    aesKey = new byte[aes.Key.Length];
                    aesIV = new byte[aes.IV.Length];
                    Array.Copy(aes.Key, aesKey, aes.Key.Length);
                    Array.Copy(aes.IV, aesIV, aes.IV.Length);

                    Server.WriteSecurityLog("AES Key Generated", $"Chave: {aesKey.Length * 8} bits, IV: {aesIV.Length * 8} bits", clientID);

                    // Combine key + IV for encryption
                    byte[] combined = new byte[aesKey.Length + aesIV.Length];
                    Array.Copy(aesKey, 0, combined, 0, aesKey.Length);
                    Array.Copy(aesIV, 0, combined, aesKey.Length, aesIV.Length);

                    // Encrypt with client's RSA public key
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
                throw new Exception($"Failed to generate encrypted AES key: {ex.Message}");
            }
        }

        /// <summary>
        /// Simple AES encryption
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
                throw new Exception($"Encryption failed: {ex.Message}");
            }
        }

        /// <summary>
        /// Simple AES decryption
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
                throw new Exception($"Decryption failed: {ex.Message}");
            }
        }

        /// <summary>
        /// TEACHER'S METHOD: Verify user password using secure hash comparison
        /// </summary>
        private bool VerifyUserPassword(User user, string inputPassword)
        {
            try
            {
                Server.WriteLog($"Verificando senha para usuário {user.Username}", "AUTH_VERIFY");

                // Password format: "hashBase64:saltBase64"
                string[] passwordParts = user.Password.Split(':');
                if (passwordParts.Length == 2)
                {
                    // New secure format: hash:salt (both Base64 encoded)
                    byte[] storedHash = Convert.FromBase64String(passwordParts[0]);
                    byte[] storedSalt = Convert.FromBase64String(passwordParts[1]);

                    Server.WriteSecurityLog("Password Verification", $"Verificando senha segura para {user.Username}", clientID);

                    // Use teacher's verification method
                    bool result = Server.VerifyPassword(inputPassword, storedHash, storedSalt);
                    Server.WriteLog($"Resultado da verificação para {user.Username}: {(result ? "SUCCESS" : "FAILED")}", "AUTH_RESULT");
                    return result;
                }
                else
                {
                    // Old plain text format (for backward compatibility)
                    Server.WriteLog($"⚠️ User {user.Username} tem senha em texto simples - deve ser migrado", "AUTH_WARNING");
                    bool result = user.Password == inputPassword;
                    Server.WriteLog($"Verificação de senha simples para {user.Username}: {(result ? "SUCCESS" : "FAILED")}", "AUTH_RESULT");
                    return result;
                }
            }
            catch (Exception ex)
            {
                Server.WriteErrorLog($"Erro ao verificar senha para {user.Username}", ex);
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

                Server.WriteLog($"Handler iniciado para cliente {clientID}", "CLIENT_HANDLER");

                while (protocolSI.GetCmdType() != ProtocolSICmdType.EOT)
                {
                    int bytesRead = networkStream.Read(protocolSI.Buffer, 0, protocolSI.Buffer.Length);
                    byte[] ack;

                    // Log dos dados recebidos
                    Server.WriteDetailedLog($"Dados recebidos do cliente {clientID}", $"Bytes: {bytesRead}, Comando: {protocolSI.GetCmdType()}", "RECEIVE");

                    switch (protocolSI.GetCmdType())
                    {
                        case ProtocolSICmdType.DATA: // Messages and Key Exchange
                            string rawData = protocolSI.GetStringFromData();

                            if (rawData.StartsWith("KEY_EXCHANGE:"))
                            {
                                // This is a key exchange request
                                string clientPublicKeyXml = rawData.Substring("KEY_EXCHANGE:".Length);
                                Server.WriteSecurityLog("Key Exchange Request", "Cliente enviou chave pública RSA", clientID);

                                try
                                {
                                    // Generate AES key and encrypt with client's RSA public key
                                    byte[] encryptedAESKey = GenerateAndEncryptAESKey(clientPublicKeyXml);
                                    string encryptedKeyBase64 = Convert.ToBase64String(encryptedAESKey);

                                    // Send encrypted AES key back to client
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
                                // This is a regular message
                                try
                                {
                                    string message;
                                    if (isEncryptionEstablished)
                                    {
                                        // Decrypt message
                                        message = DecryptWithAES(rawData);
                                        Server.WriteDetailedLog($"Mensagem encriptada recebida do cliente {clientID}", $"Conteúdo: {message}", "MSG_ENCRYPTED");
                                    }
                                    else
                                    {
                                        // Plain message
                                        message = rawData;
                                        Server.WriteDetailedLog($"Mensagem simples recebida do cliente {clientID}", $"Conteúdo: {message}", "MSG_PLAIN");
                                    }

                                    // Criar mensagem formatada com nome do user
                                    string formattedMessage;
                                    if (_userId > 0 && _username != null)
                                    {
                                        formattedMessage = $"{_username}: {message}";
                                        Server.WriteLog($"Mensagem do usuário {_username} (ID: {_userId}): {message}", "USER_MESSAGE");
                                    }
                                    else
                                    {
                                        formattedMessage = $"Cliente {clientID}: {message}";
                                        Server.WriteLog($"Mensagem do cliente anônimo {clientID}: {message}", "ANON_MESSAGE");
                                    }

                                    // Enviar para todos os outros clientes
                                    Server.BroadcastMessage(formattedMessage, clientID);

                                    ack = protocolSI.Make(ProtocolSICmdType.ACK);
                                    networkStream.Write(ack, 0, ack.Length);
                                    Server.WriteDetailedLog($"ACK enviado para cliente {clientID}", "Resposta a mensagem", "PROTOCOL");
                                }
                                catch (Exception ex)
                                {
                                    Server.WriteErrorLog($"Erro ao processar mensagem do cliente {clientID}", ex);
                                    ack = protocolSI.Make(ProtocolSICmdType.ACK);
                                    networkStream.Write(ack, 0, ack.Length);
                                }
                            }
                            break;

                        case ProtocolSICmdType.USER_OPTION_1: // Encrypted Login
                            try
                            {
                                string authData;
                                if (isEncryptionEstablished)
                                {
                                    // Decrypt login data
                                    string encryptedAuthData = protocolSI.GetStringFromData();
                                    authData = DecryptWithAES(encryptedAuthData);
                                    Server.WriteLog($"Dados de login encriptados recebidos do cliente {clientID}", "LOGIN_ENCRYPTED");
                                }
                                else
                                {
                                    // Plain login data (backward compatibility)
                                    authData = protocolSI.GetStringFromData();
                                    Server.WriteLog($"Dados de login simples recebidos do cliente {clientID}", "LOGIN_PLAIN");
                                }

                                string[] credentials = authData.Split(':');

                                if (credentials.Length == 2)
                                {
                                    string username = credentials[0];
                                    string password = credentials[1];

                                    Server.WriteLog($"Tentativa de login: User: {username}, Cliente: {clientID}", "LOGIN_ATTEMPT");

                                    // Verificar credenciais no base de dados usando método do professor
                                    using (var dbContext = new ApplicationDbContext())
                                    {
                                        var user = dbContext.Users.FirstOrDefault(u => u.Username == username);

                                        if (user != null && VerifyUserPassword(user, password))
                                        {
                                            // Login bem-sucedido
                                            Server.WriteLog($"Login bem-sucedido para User: {username}, Cliente: {clientID}", "LOGIN_SUCCESS");
                                            _userId = user.Id;
                                            _username = user.Username;

                                            // Prepare response data
                                            string responseData = $"{user.Id}:{user.Username}";

                                            if (isEncryptionEstablished)
                                            {
                                                // Send encrypted response
                                                string encryptedResponse = EncryptWithAES(responseData);
                                                byte[] response = protocolSI.Make(ProtocolSICmdType.USER_OPTION_2, encryptedResponse);
                                                networkStream.Write(response, 0, response.Length);
                                                Server.WriteLog($"Resposta de login encriptada enviada para {username}", "LOGIN_RESPONSE");
                                            }
                                            else
                                            {
                                                // Send plain response
                                                byte[] response = protocolSI.Make(ProtocolSICmdType.USER_OPTION_2, responseData);
                                                networkStream.Write(response, 0, response.Length);
                                                Server.WriteLog($"Resposta de login simples enviada para {username}", "LOGIN_RESPONSE");
                                            }

                                            // Avisar outros clientes que este user entrou
                                            Server.BroadcastMessage($"🔐 !!! {username} entrou no chat seguro !!!", clientID);
                                        }
                                        else
                                        {
                                            // Login falhou
                                            Server.WriteLog($"Login falhou para User: {username}, Cliente: {clientID}", "LOGIN_FAILED");

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

                        case ProtocolSICmdType.USER_OPTION_3: // Encrypted Register
                            try
                            {
                                string regData;
                                if (isEncryptionEstablished)
                                {
                                    // Decrypt registration data
                                    string encryptedRegData = protocolSI.GetStringFromData();
                                    regData = DecryptWithAES(encryptedRegData);
                                    Server.WriteLog($"Dados de registro encriptados recebidos do cliente {clientID}", "REGISTER_ENCRYPTED");
                                }
                                else
                                {
                                    // Plain registration data (backward compatibility)
                                    regData = protocolSI.GetStringFromData();
                                    Server.WriteLog($"Dados de registro simples recebidos do cliente {clientID}", "REGISTER_PLAIN");
                                }

                                string[] regCredentials = regData.Split(':');

                                if (regCredentials.Length == 2)
                                {
                                    string regUsername = regCredentials[0];
                                    string regPassword = regCredentials[1];

                                    Server.WriteLog($"Tentativa de registro: User: {regUsername}, Cliente: {clientID}", "REGISTER_ATTEMPT");

                                    // Verificar se o usuário já existe e criar novo se não existir
                                    using (var dbContext = new ApplicationDbContext())
                                    {
                                        // Verificar se o username já existe
                                        var existingUser = dbContext.Users
                                            .FirstOrDefault(u => u.Username == regUsername);

                                        string responseMessage;
                                        if (existingUser == null)
                                        {
                                            try
                                            {
                                                // Username não existe, criar novo usuário com senha segura
                                                byte[] salt = Server.GenerateSalt();
                                                byte[] hash = Server.GenerateSaltedHash(regPassword, salt);

                                                // Store as Base64 strings (format: hash:salt)
                                                string hashBase64 = Convert.ToBase64String(hash);
                                                string saltBase64 = Convert.ToBase64String(salt);

                                                var newUser = new User
                                                {
                                                    Username = regUsername,
                                                    Password = $"{hashBase64}:{saltBase64}"
                                                };

                                                dbContext.Users.Add(newUser);
                                                dbContext.SaveChanges();

                                                Server.WriteLog($"Usuário {regUsername} registrado com sucesso (PBKDF2)", "REGISTER_SUCCESS");
                                                responseMessage = "SUCCESS";
                                            }
                                            catch (Exception ex)
                                            {
                                                Server.WriteErrorLog($"Erro ao salvar usuário {regUsername}", ex);
                                                responseMessage = "FAILURE";
                                            }
                                        }
                                        else
                                        {
                                            // Username já existe
                                            Server.WriteLog($"Registro falhou: Username {regUsername} já existe", "REGISTER_FAILED");
                                            responseMessage = "FAILURE";
                                        }

                                        // Send response (encrypted or plain)
                                        if (isEncryptionEstablished)
                                        {
                                            string encryptedResponse = EncryptWithAES(responseMessage);
                                            byte[] response = protocolSI.Make(ProtocolSICmdType.USER_OPTION_4, encryptedResponse);
                                            networkStream.Write(response, 0, response.Length);
                                            Server.WriteLog($"Resposta de registro encriptada enviada: {responseMessage}", "REGISTER_RESPONSE");
                                        }
                                        else
                                        {
                                            byte[] response = protocolSI.Make(ProtocolSICmdType.USER_OPTION_4, responseMessage);
                                            networkStream.Write(response, 0, response.Length);
                                            Server.WriteLog($"Resposta de registro simples enviada: {responseMessage}", "REGISTER_RESPONSE");
                                        }
                                    }
                                }
                                else
                                {
                                    // Formato inválido
                                    Server.WriteLog($"Formato de dados de registro inválido do cliente {clientID}", "REGISTER_ERROR");
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
                                Server.WriteErrorLog($"Erro ao processar registro do cliente {clientID}", ex);
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
                Server.WriteErrorLog($"Erro no handler do cliente {clientID}", ex);
            }
            finally
            {
                // Log da desconexão
                if (_userId > 0 && _username != null)
                {
                    Server.WriteLog($"Usuario {_username} (ID: {_userId}) desconectou - Cliente {clientID}", "USER_DISCONNECT");
                }
                else
                {
                    Server.WriteLog($"Cliente anônimo {clientID} desconectou", "CLIENT_DISCONNECT");
                }

                // Remover este cliente da lista ao desconectar
                Server.RemoveClient(this);

                // Notificar outros users que este saiu (se estava logado)
                if (_userId > 0 && _username != null)
                {
                    Server.BroadcastMessage($"🔐 *** {_username} saiu do chat seguro ***");
                }

                try
                {
                    client.Close();
                    Server.WriteLog($"Conexão fechada para cliente {clientID}", "CONNECTION");
                }
                catch (Exception ex)
                {
                    Server.WriteErrorLog($"Erro ao fechar conexão do cliente {clientID}", ex);
                }
            }
        }
    }
}