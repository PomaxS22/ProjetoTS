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

namespace Server
{
    class Server
    {
        private const int PORT = 10000;
        // Adicionar DbContext
        private static ApplicationDbContext DbContext;

        // Lista estática para armazenar os handlers de cliente
        private static readonly List<ClientHandler> connectedClients = new List<ClientHandler>();

        // Método para adicionar cliente à lista
        public static void AddClient(ClientHandler client)
        {
            lock (connectedClients)
            {
                connectedClients.Add(client);
            }
        }

        // Método para remover cliente da lista
        public static void RemoveClient(ClientHandler client)
        {
            lock (connectedClients)
            {
                connectedClients.Remove(client);
            }
        }

        // Método para enviar mensagem a todos os clientes
        public static void BroadcastMessage(string message, int excludeClientId = -1)
        {
            lock (connectedClients)
            {
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
                Console.WriteLine("Iniciando servidor...");

                // Configurar o diretório de dados
                AppDomain.CurrentDomain.SetData("DataDirectory",
                    System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "App_Data"));

                // Criar o diretório se não existir
                string dataDir = AppDomain.CurrentDomain.GetData("DataDirectory").ToString();
                if (!System.IO.Directory.Exists(dataDir))
                {
                    System.IO.Directory.CreateDirectory(dataDir);
                    Console.WriteLine("Diretório App_Data criado em: " + dataDir);
                }

                // Configurar a inicialização do base de dados
                Database.SetInitializer(new CreateDatabaseIfNotExists<ApplicationDbContext>());

                // Inicializar e garantir que o base de dados existe
                using (var dbContext = new ApplicationDbContext())
                {
                    Console.WriteLine("Tentando criar base de dados se não existir...");
                    dbContext.Database.CreateIfNotExists();
                    Console.WriteLine("Verificação de base de dados concluída.");

                    IPEndPoint endpoint = new IPEndPoint(IPAddress.Any, PORT);
                    TcpListener listener = new TcpListener(endpoint);
                    Console.WriteLine("Iniciando listener na porta " + PORT);
                    listener.Start();
                    Console.WriteLine("SERVER READY");
                    int clientCounter = 0;

                    while (true)
                    {
                        Console.WriteLine("Aguardando conexão de cliente...");
                        TcpClient client = listener.AcceptTcpClient();
                        clientCounter++;
                        Console.WriteLine("Client {0} connected", clientCounter);
                        ClientHandler clientHandler = new ClientHandler(client, clientCounter);
                        clientHandler.Handle();
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("ERRO: " + ex.Message);
                Console.WriteLine("Stack Trace: " + ex.StackTrace);

                if (ex.InnerException != null)
                {
                    Console.WriteLine("Inner Exception: " + ex.InnerException.Message);
                    Console.WriteLine("Inner Stack Trace: " + ex.InnerException.StackTrace);
                }
            }
            finally
            {
                Console.WriteLine("Pressione qualquer tecla para sair...");
                Console.ReadKey();
            }
        }
    }

    class ClientHandler
    {
        private TcpClient client;
        private int clientID;
        private int _userId = -1; // ID do usar logado
        private string _username = null; // Nome do user logado

        // Propriedade pública para acessar o ID do cliente a partir da classe Server
        public int ClientID { get { return clientID; } }

        public ClientHandler(TcpClient client, int clientID)
        {
            this.client = client;
            this.clientID = clientID;

            // Adicionar este cliente à lista de clientes conectados
            Server.AddClient(this);
        }

        // Método para enviar uma mensagem para este cliente específico
        public void SendMessage(string message)
        {
            try
            {
                NetworkStream ns = client.GetStream();
                ProtocolSI ps = new ProtocolSI();

                byte[] packet = ps.Make(ProtocolSICmdType.DATA, message);
                ns.Write(packet, 0, packet.Length);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Erro ao enviar mensagem para cliente {clientID}: {ex.Message}");
            }
        }

        public void Handle()
        {
            Thread thread = new Thread(threadHandler);
            thread.Start();
        }

        private void threadHandler()
        {
            try
            {
                NetworkStream networkStream = this.client.GetStream();
                ProtocolSI protocolSI = new ProtocolSI();

                while (protocolSI.GetCmdType() != ProtocolSICmdType.EOT)
                {
                    int bytesRead = networkStream.Read(protocolSI.Buffer, 0, protocolSI.Buffer.Length);
                    byte[] ack;

                    switch (protocolSI.GetCmdType())
                    {
                        case ProtocolSICmdType.DATA:
                            string message = protocolSI.GetStringFromData();
                            Console.WriteLine("Client " + clientID + ": " + message);

                            // Criar mensagem formatada com nome do user (se estiver logado)
                            string formattedMessage;
                            if (_userId > 0 && _username != null)
                            {
                                formattedMessage = $"{_username}: {message}";
                            }
                            else
                            {
                                formattedMessage = $"Cliente {clientID}: {message}";
                            }

                            // Enviar para todos os outros clientes
                            Server.BroadcastMessage(formattedMessage, clientID);

                            ack = protocolSI.Make(ProtocolSICmdType.ACK);
                            networkStream.Write(ack, 0, ack.Length);
                            break;

                        case ProtocolSICmdType.USER_OPTION_1: // Login
                            string authData = protocolSI.GetStringFromData();
                            string[] credentials = authData.Split(':');

                            if (credentials.Length == 2)
                            {
                                string username = credentials[0];
                                string password = credentials[1];

                                Console.WriteLine($"Tentativa de login: User: {username}");

                                // Verificar credenciais no base de dados
                                using (var dbContext = new ApplicationDbContext())
                                {
                                    var user = dbContext.Users
                                        .FirstOrDefault(u => u.Username == username && u.Password == password);

                                    if (user != null)
                                    {
                                        // Login bem-sucedido
                                        Console.WriteLine($"Login bem-sucedido para User: {username}");
                                        _userId = user.Id;
                                        _username = user.Username;

                                        // Enviar resposta de sucesso com ID e nome do User
                                        string responseData = $"{user.Id}:{user.Username}";
                                        byte[] response = protocolSI.Make(ProtocolSICmdType.USER_OPTION_2, responseData);
                                        networkStream.Write(response, 0, response.Length);

                                        // Avisar outros clientes que este user entrou
                                        Server.BroadcastMessage($" !!! {username} entrou no chat !!!", clientID);
                                    }
                                    else
                                    {
                                        // Login falhou
                                        Console.WriteLine($"Login falhou para User: {username}");

                                        // Enviar resposta de falha
                                        byte[] response = protocolSI.Make(ProtocolSICmdType.ACK);
                                        networkStream.Write(response, 0, response.Length);
                                    }
                                }
                            }
                            else
                            {
                                // Formato inválido
                                Console.WriteLine("Formato de dados de autenticação inválido");
                                byte[] response = protocolSI.Make(ProtocolSICmdType.ACK);
                                networkStream.Write(response, 0, response.Length);
                            }
                            break;

                        case ProtocolSICmdType.USER_OPTION_3: // Register
                            string regData = protocolSI.GetStringFromData();
                            string[] regCredentials = regData.Split(':');

                            if (regCredentials.Length == 2)
                            {
                                string regUsername = regCredentials[0];
                                string regPassword = regCredentials[1];

                                Console.WriteLine($"Tentativa de registro: User: {regUsername}");

                                // Verificar se o usuário já existe e criar novo se não existir
                                using (var dbContext = new ApplicationDbContext())
                                {
                                    // Verificar se o username já existe
                                    var existingUser = dbContext.Users
                                        .FirstOrDefault(u => u.Username == regUsername);

                                    if (existingUser == null)
                                    {
                                        try
                                        {
                                            // Username não existe, criar novo usuário
                                            var newUser = new User
                                            {
                                                Username = regUsername,
                                                Password = regPassword
                                            };

                                            dbContext.Users.Add(newUser);
                                            dbContext.SaveChanges();

                                            Console.WriteLine($"Usuário {regUsername} registrado com sucesso!");

                                            // Enviar resposta de sucesso
                                            byte[] response = protocolSI.Make(ProtocolSICmdType.USER_OPTION_4, "SUCCESS");
                                            networkStream.Write(response, 0, response.Length);
                                        }
                                        catch (Exception ex)
                                        {
                                            Console.WriteLine($"Erro ao salvar usuário {regUsername}: {ex.Message}");

                                            // Enviar resposta de falha
                                            byte[] response = protocolSI.Make(ProtocolSICmdType.USER_OPTION_4, "FAILURE");
                                            networkStream.Write(response, 0, response.Length);
                                        }
                                    }
                                    else
                                    {
                                        // Username já existe
                                        Console.WriteLine($"Registro falhou: Username {regUsername} já existe");

                                        // Enviar resposta de falha
                                        byte[] response = protocolSI.Make(ProtocolSICmdType.USER_OPTION_4, "FAILURE");
                                        networkStream.Write(response, 0, response.Length);
                                    }
                                }
                            }
                            else
                            {
                                // Formato inválido
                                Console.WriteLine("Formato de dados de registro inválido");
                                byte[] response = protocolSI.Make(ProtocolSICmdType.USER_OPTION_4, "FAILURE");
                                networkStream.Write(response, 0, response.Length);
                            }
                            break;

                        case ProtocolSICmdType.EOT:
                            Console.WriteLine("Ending Thread from Client {0}", clientID);
                            ack = protocolSI.Make(ProtocolSICmdType.ACK);
                            networkStream.Write(ack, 0, ack.Length);
                            break;
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Erro no handler do cliente {0}: {1}", clientID, ex.Message);
            }
            finally
            {
                // Remover este cliente da lista ao desconectar
                Server.RemoveClient(this);

                // Notificar outros users que este saiu (se estava logado)
                if (_userId > 0 && _username != null)
                {
                    Server.BroadcastMessage($"*** {_username} saiu do chat ***");
                }

                client.Close();
            }
        }
    }
}