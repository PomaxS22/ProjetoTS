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
        private const int PORT = 10000;
        NetworkStream networkStream;
        ProtocolSI protocolSI;
        TcpClient client;

        // Variável para armazenar o ID do usuário logado
        private int loggedUserId = -1;
        private string loggedUsername = null;

        // Thread para receber mensagens
        private Thread receiveThread;
        private bool isRunning = false;

        public Client()
        {
            InitializeComponent();

            // Configurar a UI inicial (mostrando apenas o login)
            SetLoginUIVisible(true);

            // A conexão será estabelecida após o login bem-sucedido
        }

        // Método para controlar a visibilidade da UI
        private void SetLoginUIVisible(bool showLoginUI)
        {
            // Painel de login
            panelLogin.Visible = showLoginUI;

            // Painel de mensagens
            panelMessage.Visible = !showLoginUI;
        }

        // Iniciar a thread de recepção de mensagens
        private void StartReceiving()
        {
            isRunning = true;
            receiveThread = new Thread(ReceiveMessages);
            receiveThread.IsBackground = true;
            receiveThread.Start();
        }

        // Método para receber mensagens
        private void ReceiveMessages()
        {
            try
            {
                while (isRunning)
                {
                    // Verificar se há dados disponíveis
                    if (networkStream.DataAvailable)
                    {
                        // Ler mensagem
                        networkStream.Read(protocolSI.Buffer, 0, protocolSI.Buffer.Length);

                        // Verificar tipo da mensagem
                        if (protocolSI.GetCmdType() == ProtocolSICmdType.DATA)
                        {
                            string message = protocolSI.GetStringFromData();

                            // Atualizar a UI com a mensagem recebida
                            UpdateChatBox(message);

                            // Enviar ACK
                            byte[] ack = protocolSI.Make(ProtocolSICmdType.ACK);
                            networkStream.Write(ack, 0, ack.Length);
                        }
                    }

                    // Pequena pausa para não sobrecarregar a CPU
                    Thread.Sleep(10);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show("Erro ao receber mensagens: " + ex.Message, "Erro", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        // Método para atualizar a caixa de chat com segurança entre threads
        private void UpdateChatBox(string message)
        {
            if (txtChatBox.InvokeRequired)
            {
                // Se estamos em outra thread, invocamos este método na thread da UI
                txtChatBox.Invoke(new Action<string>(UpdateChatBox), message);
            }
            else
            {
                // Estamos na thread da UI, podemos atualizar diretamente
                txtChatBox.AppendText(message + Environment.NewLine);
                // Rolar para o final
                txtChatBox.SelectionStart = txtChatBox.Text.Length;
                txtChatBox.ScrollToCaret();
            }
        }

        // Método para autenticar o usuário com o servidor
        private bool AuthenticateUser(string username, string password)
        {
            try
            {
                // Conectar ao servidor
                ConnectToServer();

                // Criar o pacote de autenticação (username:password)
                string authData = $"{username}:{password}";
                byte[] packet = protocolSI.Make(ProtocolSICmdType.USER_OPTION_1, authData);

                // Enviar pacote
                networkStream.Write(packet, 0, packet.Length);

                // Aguardar resposta
                networkStream.Read(protocolSI.Buffer, 0, protocolSI.Buffer.Length);

                // Verificar resposta
                if (protocolSI.GetCmdType() == ProtocolSICmdType.USER_OPTION_2)
                {
                    // Autenticação bem-sucedida
                    string userData = protocolSI.GetStringFromData();
                    string[] parts = userData.Split(':');

                    if (parts.Length >= 2)
                    {
                        loggedUserId = int.Parse(parts[0]);
                        loggedUsername = parts[1];

                        // Iniciar thread de recepção de mensagens
                        StartReceiving();

                        return true;
                    }
                }

                // Se chegou aqui, a autenticação falhou
                return false;
            }
            catch (Exception ex)
            {
                MessageBox.Show("Erro ao autenticar: " + ex.Message, "Erro", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return false;
            }
        }

        private void btnLogin_Click_1(object sender, EventArgs e)
        {
            string username = txtUsername.Text;
            string password = txtPassword.Text;

            if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password))
            {
                MessageBox.Show("Por favor, preencha o usuário e senha.", "Aviso", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            // Tentar autenticar com o servidor
            if (AuthenticateUser(username, password))
            {
                // Login bem-sucedido - alterar a UI e já estamos conectados
                SetLoginUIVisible(false);
            }
            else
            {
                MessageBox.Show("Usuário ou senha incorretos.", "Erro", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        // Método para conectar ao servidor
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
                throw; // Propagar o erro para ser capturado pelo chamador
            }
        }

        // Método do botão enviar
        private void buttonSend_Click(object sender, EventArgs e)
        {
            string msg = textBoxMessage.Text;
            if (string.IsNullOrWhiteSpace(msg))
                return;

            textBoxMessage.Clear();
            byte[] packet = protocolSI.Make(ProtocolSICmdType.DATA, msg); //cria uma mensagem/pacote de um tipo específico
            networkStream.Write(packet, 0, packet.Length);

            // Aguardar ACK
            while (protocolSI.GetCmdType() != ProtocolSICmdType.ACK)
            {
                networkStream.Read(protocolSI.Buffer, 0, protocolSI.Buffer.Length);
            }

            // Mostrar mensagem enviada no próprio chat (opcional)
            UpdateChatBox($"Eu: {msg}");
        }

        //Método para fechar o Client
        private void CloseClient()
        {
            try
            {
                // Parar thread de recepção
                isRunning = false;
                if (receiveThread != null && receiveThread.IsAlive)
                {
                    receiveThread.Join(1000); // Esperar até 1 segundo pela thread terminar
                }

                if (networkStream != null && client != null && client.Connected)
                {
                    // Definição da variável eot (End of Transmission) do tipo array de byte.
                    // Utilização do método Make. ProtocolSICmdType serve para enviar dados
                    byte[] eot = protocolSI.Make(ProtocolSICmdType.EOT);

                    // A classe NetworkStream disponibiliza métodos para enviar/receber dados através de socket Stream
                    // O Socket de rede é um endpoint interno para envio e recepção de dados com um nó/computador presente na rede.
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

        //Método para fechar o formulário
        private void Client_FormClosing(object sender, FormClosingEventArgs e)
        {
            // Chamar a função para fechar o Client
            CloseClient();
        }

        //Método para o Botão para sair
        private void buttonQuit_Click(object sender, EventArgs e)
        {
            // Chamar a função para fechar o Client e associar a este próprio botão
            CloseClient();
            this.Close();
        }
    }
}