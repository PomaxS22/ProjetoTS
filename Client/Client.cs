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
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Security.Cryptography;

namespace Client
{
    public partial class Client : Form
    {
        NetworkStream networkStream;
        ProtocolSI protocolSI;
        TcpClient client;

        // Variáveis de encriptação simples
        private byte[] aesKey;
        private byte[] aesIV;

        // Informações do utilizador recebidas do formulário de Login
        private int loggedUserId = -1;
        private string loggedUsername = null;

        // Thread para receber mensagens
        private Thread receiveThread;
        private volatile bool isRunning = false;

        // Construtor actualizado que aceita chaves AES
        public Client(int userId, string username, TcpClient tcpClient, NetworkStream stream, ProtocolSI protocol, byte[] aesKeyParam, byte[] aesIVParam)
        {
            InitializeComponent();

            // Definir informações do utilizador
            loggedUserId = userId;
            loggedUsername = username;

            // Definir componentes de rede
            client = tcpClient;
            networkStream = stream;
            protocolSI = protocol;

            // Definir chaves de encriptação
            aesKey = aesKeyParam;
            aesIV = aesIVParam;

            // Actualizar título do formulário com nome de utilizador
            this.Text = $"Chat Seguro - {loggedUsername}";

            // Etiqueta do nome de utilizador
            labelUserName.Text = loggedUsername;

            // Iniciar recepção de mensagens
            StartReceiving();
        }

        // Iniciar a thread de recepção de mensagens
        private void StartReceiving()
        {
            isRunning = true;
            receiveThread = new Thread(ReceiveMessages)
            {
                IsBackground = true,
                Name = $"ReceiveThread_{loggedUsername}"
            };
            receiveThread.Start();
        }

        // Método para receber mensagens encriptadas
        private void ReceiveMessages()
        {
            try
            {
                while (isRunning && networkStream != null && client != null && client.Connected)
                {
                    try
                    {
                        // Verificar se há dados disponíveis
                        if (networkStream.DataAvailable)
                        {
                            // Ler mensagem
                            byte[] buffer = new byte[protocolSI.Buffer.Length];
                            int bytesRead = networkStream.Read(buffer, 0, buffer.Length);

                            if (bytesRead > 0)
                            {
                                // Copiar para buffer do protocolo
                                Array.Copy(buffer, protocolSI.Buffer, Math.Min(buffer.Length, protocolSI.Buffer.Length));

                                // Verificar tipo de mensagem
                                if (protocolSI.GetCmdType() == ProtocolSICmdType.DATA)
                                {
                                    try
                                    {
                                        // Obter mensagem encriptada e desencriptá-la
                                        string encryptedMessage = protocolSI.GetStringFromData();
                                        string decryptedMessage = DecryptWithAES(encryptedMessage);

                                        // Actualizar interface com mensagem desencriptada
                                        UpdateChatBoxSafe($"🔐 {decryptedMessage}");
                                    }
                                    catch (Exception decryptEx)
                                    {
                                        // Se a desencriptação falhar, mostrar como encriptada
                                        UpdateChatBoxSafe($"[MENSAGEM ENCRIPTADA - Erro: {decryptEx.Message}]");
                                    }

                                    // Enviar ACK
                                    byte[] ack = protocolSI.Make(ProtocolSICmdType.ACK);
                                    networkStream.Write(ack, 0, ack.Length);
                                }
                            }
                        }

                        // Pequena pausa para não sobrecarregar o CPU
                        Thread.Sleep(100);
                    }
                    catch (Exception ex)
                    {
                        if (isRunning) // Apenas registar se ainda devemos estar a correr
                        {
                            Console.WriteLine($"Erro na thread de recepção para {loggedUsername}: {ex.Message}");
                        }
                        Thread.Sleep(1000); // Aguardar um pouco antes de tentar novamente
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Erro fatal na thread de recepção para {loggedUsername}: {ex.Message}");
            }
        }

        // Método thread-safe para actualizar caixa de chat
        private void UpdateChatBoxSafe(string message)
        {
            try
            {
                if (this.IsDisposed || this.Disposing || !this.IsHandleCreated)
                    return;

                if (this.InvokeRequired)
                {
                    this.BeginInvoke(new Action(() =>
                    {
                        try
                        {
                            if (!this.IsDisposed && txtChatBox != null)
                            {
                                // Adicionar timestamp
                                string timestampedMessage = $"[{DateTime.Now:HH:mm:ss}] {message}";
                                txtChatBox.AppendText(timestampedMessage + Environment.NewLine);
                                txtChatBox.SelectionStart = txtChatBox.Text.Length;
                                txtChatBox.ScrollToCaret();
                            }
                        }
                        catch { /* Ignorar erros de actualização da interface */ }
                    }));
                }
                else
                {
                    if (txtChatBox != null)
                    {
                        // Adicionar timestamp
                        string timestampedMessage = $"[{DateTime.Now:HH:mm:ss}] {message}";
                        txtChatBox.AppendText(timestampedMessage + Environment.NewLine);
                        txtChatBox.SelectionStart = txtChatBox.Text.Length;
                        txtChatBox.ScrollToCaret();
                    }
                }
            }
            catch
            {
                // Ignorar todos os erros para prevenir travamentos
            }
        }

        // Enviar mensagem encriptada
        private void buttonSend_Click(object sender, EventArgs e)
        {
            string msg = textBoxMessage.Text.Trim();
            if (string.IsNullOrWhiteSpace(msg))
                return;

            // Limpar imediatamente
            textBoxMessage.Clear();

            // Enviar mensagem encriptada em segundo plano
            Task.Run(() =>
            {
                try
                {
                    if (networkStream != null && client != null && client.Connected)
                    {
                        // Encriptar mensagem com AES
                        string encryptedMessage = EncryptWithAES(msg);

                        // Enviar mensagem encriptada
                        byte[] packet = protocolSI.Make(ProtocolSICmdType.DATA, encryptedMessage);
                        networkStream.Write(packet, 0, packet.Length);

                        // Mostrar mensagem enviada com indicador de encriptação
                        UpdateChatBoxSafe($"Eu: {msg}");
                    }
                }
                catch (Exception ex)
                {
                    // Mostrar erro se o envio falhar
                    UpdateChatBoxSafe($"[ERRO] Falha ao enviar: {msg} - {ex.Message}");
                    Console.WriteLine($"Erro de envio para {loggedUsername}: {ex.Message}");
                }
            });

            // Focar de volta na entrada de mensagem
            textBoxMessage.Focus();
        }

        /// <summary>
        /// Encriptação AES simples para mensagens
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
                    return Convert.ToBase64String(encryptedBytes);
                }
            }
            catch (Exception ex)
            {
                throw new Exception($"Encriptação falhou: {ex.Message}");
            }
        }

        /// <summary>
        /// Desencriptação AES simples para mensagens
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
                    return Encoding.UTF8.GetString(decryptedBytes);
                }
            }
            catch (Exception ex)
            {
                throw new Exception($"Desencriptação falhou: {ex.Message}");
            }
        }

        // Método para fechar ligação do cliente
        private void CloseClient()
        {
            try
            {
                isRunning = false;

                // Fechar recursos de rede primeiro
                if (networkStream != null)
                {
                    try
                    {
                        if (client != null && client.Connected)
                        {
                            byte[] eot = protocolSI.Make(ProtocolSICmdType.EOT);
                            networkStream.Write(eot, 0, eot.Length);
                        }
                    }
                    catch { /* Ignorar */ }

                    networkStream.Close();
                    networkStream = null;
                }

                if (client != null)
                {
                    client.Close();
                    client = null;
                }

                // Aguardar que a thread termine
                if (receiveThread != null && receiveThread.IsAlive)
                {
                    receiveThread.Join(1000);
                }
            }
            catch
            {
                // Ignorar erros de limpeza
            }
        }

        // Evento de fecho do formulário
        private void Client_FormClosing(object sender, FormClosingEventArgs e)
        {
            CloseClient();
        }

        // Criar novo login (processo separado)
        private void btnAddUser_Click(object sender, EventArgs e)
        {
            try
            {
                // Criar novo formulário de login numa thread separada para evitar interferência
                Thread newLoginThread = new Thread(() =>
                {
                    try
                    {
                        Application.SetCompatibleTextRenderingDefault(false);
                        Login newLoginForm = new Login();
                        Application.Run(newLoginForm);
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Erro ao criar novo login: {ex.Message}");
                    }
                })
                {
                    IsBackground = false
                };

                newLoginThread.Start();
            }
            catch (Exception ex)
            {
                MessageBox.Show("Erro ao abrir nova janela de login: " + ex.Message, "Erro",
                    MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        // Adiciona estes métodos à tua classe Client.cs

        #region Efeitos Visuais e Eventos

        /// <summary>
        /// Efeito visual quando o campo de mensagem ganha foco
        /// </summary>
        private void textBoxMessage_Enter(object sender, EventArgs e)
        {
            TextBox txt = sender as TextBox;
            if (txt != null)
            {
                txt.BackColor = Color.White; // Muda para branco quando focado

                // Adicionar uma borda visual simulada (opcional)
                txt.Padding = new Padding(5);
            }
        }

        /// <summary>
        /// Efeito visual quando o campo de mensagem perde foco
        /// </summary>
        private void textBoxMessage_Leave(object sender, EventArgs e)
        {
            TextBox txt = sender as TextBox;
            if (txt != null)
            {
                txt.BackColor = Color.FromArgb(248, 249, 250); // Volta ao cinza claro
                txt.Padding = new Padding(0);
            }
        }

        /// <summary>
        /// Permite enviar mensagem pressionando Enter
        /// </summary>
        private void textBoxMessage_KeyPress(object sender, KeyPressEventArgs e)
        {
            if (e.KeyChar == (char)13) // Enter key
            {
                e.Handled = true; // Previne o "beep" do sistema

                // Verificar se não é Shift+Enter (para quebra de linha)
                if (!ModifierKeys.HasFlag(Keys.Shift))
                {
                    // Enviar a mensagem
                    buttonSend_Click(sender, e);
                }
                else
                {
                    // Permitir quebra de linha com Shift+Enter
                    textBoxMessage.AppendText(Environment.NewLine);
                }
            }
        }

        /// <summary>
        /// Atualiza o indicador de status online/offline
        /// </summary>
        private void UpdateConnectionStatus(bool isConnected)
        {
            if (this.InvokeRequired)
            {
                this.BeginInvoke(new Action(() => UpdateConnectionStatus(isConnected)));
                return;
            }

            if (lblOnlineIndicator != null)
            {
                if (isConnected)
                {
                    lblOnlineIndicator.Text = "🟢 Conectado";
                    lblOnlineIndicator.ForeColor = Color.FromArgb(40, 167, 69); // Verde
                }
                else
                {
                    lblOnlineIndicator.Text = "🔴 Desconectado";
                    lblOnlineIndicator.ForeColor = Color.FromArgb(220, 53, 69); // Vermelho
                }
            }
        }

        /// <summary>
        /// Atualiza o título da janela com informações do usuário
        /// </summary>
        private void UpdateWindowTitle()
        {
            if (this.InvokeRequired)
            {
                this.BeginInvoke(new Action(UpdateWindowTitle));
                return;
            }

            if (!string.IsNullOrEmpty(loggedUsername))
            {
                this.Text = $"🔐 Chat Seguro - {loggedUsername}";
            }
            else
            {
                this.Text = "🔐 Chat Seguro";
            }
        }

        /// <summary>
        /// Adiciona animação sutil ao botão de enviar
        /// </summary>
        private void AnimateSendButton()
        {
            if (this.InvokeRequired)
            {
                this.BeginInvoke(new Action(AnimateSendButton));
                return;
            }

            // Simular feedback visual do envio
            var originalColor = buttonSend.BackColor;
            buttonSend.BackColor = Color.FromArgb(40, 167, 69); // Verde temporário
            buttonSend.Text = "✅ Enviado";

            // Timer para voltar ao normal
            var timer = new System.Windows.Forms.Timer();
            timer.Interval = 500; // 500ms
            timer.Tick += (s, e) =>
            {
                buttonSend.BackColor = originalColor;
                buttonSend.Text = "📤 Enviar";
                timer.Stop();
                timer.Dispose();
            };
            timer.Start();
        }

        #endregion

        #region Métodos Auxiliares para UI

        /// <summary>
        /// Limpa o campo de mensagem com efeito
        /// </summary>
        private void ClearMessageField()
        {
            if (this.InvokeRequired)
            {
                this.BeginInvoke(new Action(ClearMessageField));
                return;
            }

            textBoxMessage.Clear();
            textBoxMessage.Focus(); // Mantém o foco no campo
        }

        /// <summary>
        /// Adiciona mensagem ao chat com formatação melhorada
        /// </summary>
        private void AddMessageToChat(string message, bool isSystemMessage = false)
        {
            if (this.InvokeRequired)
            {
                this.BeginInvoke(new Action(() => AddMessageToChat(message, isSystemMessage)));
                return;
            }

            if (txtChatBox != null)
            {
                // Limpar mensagem de boas-vindas na primeira mensagem
                if (txtChatBox.Text.Contains("Bem-vindo ao chat seguro"))
                {
                    txtChatBox.Clear();
                }

                string timestamp = DateTime.Now.ToString("HH:mm:ss");
                string formattedMessage;

                if (isSystemMessage)
                {
                    formattedMessage = $"[{timestamp}] {message}";
                }
                else
                {
                    formattedMessage = $"[{timestamp}] {message}";
                }

                txtChatBox.AppendText(formattedMessage + Environment.NewLine);
                txtChatBox.SelectionStart = txtChatBox.Text.Length;
                txtChatBox.ScrollToCaret();
            }
        }

        #endregion

    }
}