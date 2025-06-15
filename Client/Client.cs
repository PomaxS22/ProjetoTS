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

        // NOVO: Variáveis para assinaturas digitais
        private RSACryptoServiceProvider rsaSignature; // Para assinar as nossas mensagens
        private Dictionary<int, RSACryptoServiceProvider> publicKeysForVerification; // Chaves públicas de outros utilizadores

        // Informações do utilizador recebidas do formulário de Login
        private int loggedUserId = -1;
        private string loggedUsername = null;

        // Thread para receber mensagens
        private Thread receiveThread;
        private volatile bool isRunning = false;

        // Construtor actualizado que aceita chaves AES e RSA para assinaturas
        public Client(int userId, string username, TcpClient tcpClient, NetworkStream stream, ProtocolSI protocol, byte[] aesKeyParam, byte[] aesIVParam, RSACryptoServiceProvider rsaKey)
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

            // NOVO: Definir chave RSA para assinaturas digitais
            rsaSignature = rsaKey;
            publicKeysForVerification = new Dictionary<int, RSACryptoServiceProvider>();

            // Actualizar título do formulário com nome de utilizador
            this.Text = $"🔐 Chat Seguro com Assinaturas - {loggedUsername}";

            // Etiqueta do nome de utilizador
            labelUserName.Text = loggedUsername;

            // Iniciar recepção de mensagens
            StartReceiving();

            // NOVO: Solicitar chaves públicas de outros utilizadores
            RequestPublicKeysFromServer();
        }

        /// <summary>
        /// NOVO: Solicitar chaves públicas de outros utilizadores para verificação de assinaturas
        /// </summary>
        private void RequestPublicKeysFromServer()
        {
            Task.Run(() =>
            {
                try
                {
                    string request = "REQUEST_PUBLIC_KEYS";
                    string encryptedRequest = EncryptWithAES(request);
                    byte[] packet = protocolSI.Make(ProtocolSICmdType.DATA, encryptedRequest);
                    networkStream.Write(packet, 0, packet.Length);
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Erro ao solicitar chaves públicas: {ex.Message}");
                }
            });
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

        // Método para receber mensagens encriptadas e verificar assinaturas
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
                                        // Obter dados encriptados
                                        string encryptedData = protocolSI.GetStringFromData();
                                        string decryptedData = DecryptWithAES(encryptedData);

                                        // NOVO: Verificar se são chaves públicas ou mensagem normal
                                        if (decryptedData.StartsWith("PUBLIC_KEYS:"))
                                        {
                                            ProcessPublicKeys(decryptedData);
                                        }
                                        else if (decryptedData.StartsWith("SIGNED_MESSAGE:"))
                                        {
                                            ProcessSignedMessage(decryptedData);
                                        }
                                        else
                                        {
                                            // Mensagem normal (compatibilidade)
                                            UpdateChatBoxSafe($"🔐 {decryptedData}");
                                        }
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

        /// <summary>
        /// NOVO: Processar chaves públicas recebidas do servidor
        /// </summary>
        private void ProcessPublicKeys(string data)
        {
            try
            {
                // Formato: PUBLIC_KEYS:userId1:publicKeyXml1|userId2:publicKeyXml2|...
                string keysData = data.Substring("PUBLIC_KEYS:".Length);
                string[] keyEntries = keysData.Split('|');

                foreach (string entry in keyEntries)
                {
                    if (string.IsNullOrEmpty(entry)) continue;

                    string[] parts = entry.Split(new char[] { ':' }, 2);
                    if (parts.Length == 2)
                    {
                        int userId = int.Parse(parts[0]);
                        string publicKeyXml = parts[1];

                        // Não adicionar a nossa própria chave
                        if (userId != loggedUserId)
                        {
                            try
                            {
                                RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
                                rsa.FromXmlString(publicKeyXml);
                                publicKeysForVerification[userId] = rsa;

                                Console.WriteLine($"✅ Chave pública do utilizador {userId} adicionada para verificação");
                            }
                            catch (Exception ex)
                            {
                                Console.WriteLine($"❌ Erro ao processar chave pública do utilizador {userId}: {ex.Message}");
                            }
                        }
                    }
                }

                UpdateChatBoxSafe($"🔑 Chaves públicas actualizadas. {publicKeysForVerification.Count} utilizadores disponíveis para verificação.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Erro ao processar chaves públicas: {ex.Message}");
            }
        }

        /// <summary>
        /// NOVO: Processar mensagem assinada digitalmente
        /// </summary>
        private void ProcessSignedMessage(string data)
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
                    string signatureBase64 = parts[4];

                    // Verificar assinatura digital
                    bool isSignatureValid = VerifyDigitalSignature(message, signatureBase64, senderId);

                    // Mostrar mensagem com indicação de validade da assinatura
                    string verificationIcon = isSignatureValid ? "✅" : "❌";
                    string verificationText = isSignatureValid ? "Assinatura Válida" : "Assinatura INVÁLIDA";

                    UpdateChatBoxSafe($"{verificationIcon} {senderName}: {message} [{verificationText}]");

                    // Log da verificação
                    Console.WriteLine($"🔍 Verificação de assinatura - Remetente: {senderName}, Válida: {isSignatureValid}");
                }
                else
                {
                    UpdateChatBoxSafe("❌ Mensagem assinada com formato inválido");
                }
            }
            catch (Exception ex)
            {
                UpdateChatBoxSafe($"❌ Erro ao processar mensagem assinada: {ex.Message}");
                Console.WriteLine($"Erro ao processar mensagem assinada: {ex.Message}");
            }
        }

        /// <summary>
        /// NOVO: Verificar assinatura digital de uma mensagem
        /// </summary>
        private bool VerifyDigitalSignature(string message, string signatureBase64, int senderId)
        {
            try
            {
                // Verificar se temos a chave pública do remetente
                if (!publicKeysForVerification.ContainsKey(senderId))
                {
                    Console.WriteLine($"⚠️ Chave pública do utilizador {senderId} não disponível para verificação");
                    return false;
                }

                RSACryptoServiceProvider senderPublicKey = publicKeysForVerification[senderId];
                byte[] messageBytes = Encoding.UTF8.GetBytes(message);
                byte[] signature = Convert.FromBase64String(signatureBase64);

                // Verificar assinatura usando SHA256
                bool isValid = senderPublicKey.VerifyData(messageBytes, new SHA256CryptoServiceProvider(), signature);

                return isValid;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Erro na verificação de assinatura: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// NOVO: Criar assinatura digital para uma mensagem
        /// </summary>
        private string CreateDigitalSignature(string message)
        {
            try
            {
                byte[] messageBytes = Encoding.UTF8.GetBytes(message);
                byte[] signature = rsaSignature.SignData(messageBytes, new SHA256CryptoServiceProvider());
                return Convert.ToBase64String(signature);
            }
            catch (Exception ex)
            {
                throw new Exception($"Falha ao criar assinatura digital: {ex.Message}");
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

        // NOVO: Enviar mensagem encriptada com assinatura digital
        private void buttonSend_Click(object sender, EventArgs e)
        {
            string msg = textBoxMessage.Text.Trim();
            if (string.IsNullOrWhiteSpace(msg))
                return;

            // Limpar imediatamente
            textBoxMessage.Clear();

            // Enviar mensagem encriptada e assinada em segundo plano
            Task.Run(() =>
            {
                try
                {
                    if (networkStream != null && client != null && client.Connected)
                    {
                        // NOVO: Criar assinatura digital da mensagem
                        string digitalSignature = CreateDigitalSignature(msg);

                        // Formato: SIGNED_MESSAGE:senderId:senderName:message:signature
                        string signedMessageData = $"SIGNED_MESSAGE:{loggedUserId}:{loggedUsername}:{msg}:{digitalSignature}";

                        // Encriptar dados da mensagem assinada
                        string encryptedMessage = EncryptWithAES(signedMessageData);

                        // Enviar mensagem encriptada e assinada
                        byte[] packet = protocolSI.Make(ProtocolSICmdType.DATA, encryptedMessage);
                        networkStream.Write(packet, 0, packet.Length);

                        // Mostrar mensagem enviada com indicador de assinatura
                        UpdateChatBoxSafe($"✅ Eu: {msg} [Assinado Digitalmente]");

                        Console.WriteLine($"📤 Mensagem assinada e enviada: {msg}");
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

                // NOVO: Limpar chaves RSA
                if (rsaSignature != null)
                {
                    rsaSignature.Dispose();
                    rsaSignature = null;
                }

                foreach (var keyPair in publicKeysForVerification)
                {
                    keyPair.Value.Dispose();
                }
                publicKeysForVerification.Clear();

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

        #region Efeitos Visuais e Eventos (mantidos do original)

        private void textBoxMessage_Enter(object sender, EventArgs e)
        {
            TextBox txt = sender as TextBox;
            if (txt != null)
            {
                txt.BackColor = Color.White;
                txt.Padding = new Padding(5);
            }
        }

        private void textBoxMessage_Leave(object sender, EventArgs e)
        {
            TextBox txt = sender as TextBox;
            if (txt != null)
            {
                txt.BackColor = Color.FromArgb(248, 249, 250);
                txt.Padding = new Padding(0);
            }
        }

        private void textBoxMessage_KeyPress(object sender, KeyPressEventArgs e)
        {
            if (e.KeyChar == (char)13) // Enter key
            {
                e.Handled = true;

                if (!ModifierKeys.HasFlag(Keys.Shift))
                {
                    buttonSend_Click(sender, e);
                }
                else
                {
                    textBoxMessage.AppendText(Environment.NewLine);
                }
            }
        }

        #endregion
    }
}