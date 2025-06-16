using EI.SI;
using System;
using System.Collections.Generic;
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

        // Variáveis de criptografia
        private byte[] aesKey;
        private byte[] aesIV;

        // Variáveis para assinaturas digitais
        private RSACryptoServiceProvider rsaSignature; // Para assinar as nossas mensagens
        private Dictionary<int, RSACryptoServiceProvider> publicKeysForVerification; // Chaves públicas de outros utilizadores

        // Dados do utilizador
        private int loggedUserId = -1;
        private string loggedUsername = null;

        // Thread para receber mensagens
        private Thread receiveThread;
        private volatile bool isRunning = false;

        public Client(int userId, string username, TcpClient tcpClient, NetworkStream stream, ProtocolSI protocol, byte[] aesKeyParam, byte[] aesIVParam, RSACryptoServiceProvider rsaKey)
        {
            InitializeComponent();

            // Definir dados do utilizador
            loggedUserId = userId;
            loggedUsername = username;

            // Definir componentes de rede
            client = tcpClient;
            networkStream = stream;
            protocolSI = protocol;

            // Definir chaves de criptografia
            aesKey = aesKeyParam;
            aesIV = aesIVParam;

            // Definir chave RSA para assinaturas
            rsaSignature = rsaKey;
            publicKeysForVerification = new Dictionary<int, RSACryptoServiceProvider>();

            // Actualizar interface
            this.Text = $"Chat - {loggedUsername}";
            labelUserName.Text = loggedUsername;

            // Iniciar recepção de mensagens
            StartReceiving();

            // Solicitar chaves públicas de outros utilizadores
            RequestPublicKeysFromServer();
        }

        // Solicitar chaves públicas para verificar assinaturas
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
                    Console.WriteLine("Solicitadas chaves públicas do servidor");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Erro ao solicitar chaves públicas: {ex.Message}");
                }
            });
        }

        // Iniciar thread de recepção de mensagens
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

        // Receber e processar mensagens
        private void ReceiveMessages()
        {
            try
            {
                while (isRunning && networkStream != null && client != null && client.Connected)
                {
                    try
                    {
                        if (networkStream.DataAvailable)
                        {
                            byte[] buffer = new byte[protocolSI.Buffer.Length];
                            int bytesRead = networkStream.Read(buffer, 0, buffer.Length);

                            if (bytesRead > 0)
                            {
                                Array.Copy(buffer, protocolSI.Buffer, Math.Min(buffer.Length, protocolSI.Buffer.Length));

                                if (protocolSI.GetCmdType() == ProtocolSICmdType.DATA)
                                {
                                    try
                                    {
                                        // Desencriptar dados recebidos
                                        string encryptedData = protocolSI.GetStringFromData();
                                        string decryptedData = DecryptWithAES(encryptedData);

                                        // Processar diferentes tipos de dados
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
                                        UpdateChatBoxSafe($"[MENSAGEM ENCRIPTADA - Erro: {decryptEx.Message}]");
                                    }

                                    // Enviar confirmação
                                    byte[] ack = protocolSI.Make(ProtocolSICmdType.ACK);
                                    networkStream.Write(ack, 0, ack.Length);
                                }
                            }
                        }
                        Thread.Sleep(100); // Pequena pausa
                    }
                    catch (Exception ex)
                    {
                        if (isRunning)
                        {
                            Console.WriteLine($"Erro na recepção para {loggedUsername}: {ex.Message}");
                        }
                        Thread.Sleep(1000);
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Erro fatal na recepção para {loggedUsername}: {ex.Message}");
            }
        }

        // Processar chaves públicas recebidas do servidor
        private void ProcessPublicKeys(string data)
        {
            try
            {
                // Formato: PUBLIC_KEYS:userId1:publicKeyXml1|userId2:publicKeyXml2|...
                string keysData = data.Substring("PUBLIC_KEYS:".Length);
                string[] keyEntries = keysData.Split('|');

                int keysProcessed = 0;
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
                                keysProcessed++;
                            }
                            catch (Exception ex)
                            {
                                Console.WriteLine($"Erro ao processar chave do utilizador {userId}: {ex.Message}");
                            }
                        }
                    }
                }

                Console.WriteLine($"{keysProcessed} chaves públicas recebidas e processadas");
                UpdateChatBoxSafe($"Chaves actualizadas. {publicKeysForVerification.Count} utilizadores disponíveis.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Erro ao processar chaves públicas: {ex.Message}");
            }
        }

        // Processar mensagem assinada digitalmente
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

                    // Mostrar mensagem com indicação da validade da assinatura
                    string verificationIcon = isSignatureValid ? "✅" : "❌";
                    UpdateChatBoxSafe($"{verificationIcon} {senderName}: {message}");
                }
                else
                {
                    UpdateChatBoxSafe("Mensagem assinada com formato inválido");
                }
            }
            catch (Exception ex)
            {
                UpdateChatBoxSafe($"Erro ao processar mensagem assinada: {ex.Message}");
            }
        }

        // Verificar assinatura digital de uma mensagem
        private bool VerifyDigitalSignature(string message, string signatureBase64, int senderId)
        {
            try
            {
                // Verificar se temos a chave pública do remetente
                if (!publicKeysForVerification.ContainsKey(senderId))
                {
                    Console.WriteLine($"Chave pública do utilizador {senderId} não disponível");
                    return false;
                }

                RSACryptoServiceProvider senderPublicKey = publicKeysForVerification[senderId];
                byte[] messageBytes = Encoding.UTF8.GetBytes(message);
                byte[] signature = Convert.FromBase64String(signatureBase64);

                // Verificar assinatura usando SHA256
                bool isValid = senderPublicKey.VerifyData(messageBytes, new SHA256CryptoServiceProvider(), signature);
                Console.WriteLine($"Verificação de assinatura do utilizador {senderId}: {(isValid ? "VÁLIDA" : "INVÁLIDA")}");
                return isValid;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Erro na verificação de assinatura: {ex.Message}");
                return false;
            }
        }

        // Criar assinatura digital para uma mensagem
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
                throw new Exception($"Falha ao criar assinatura: {ex.Message}");
            }
        }

        // Actualizar caixa de chat de forma thread-safe
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
                                string timestampedMessage = $"[{DateTime.Now:HH:mm}] {message}";
                                txtChatBox.AppendText(timestampedMessage + Environment.NewLine);
                                txtChatBox.SelectionStart = txtChatBox.Text.Length;
                                txtChatBox.ScrollToCaret();
                            }
                        }
                        catch { }
                    }));
                }
                else
                {
                    if (txtChatBox != null)
                    {
                        string timestampedMessage = $"[{DateTime.Now:HH:mm}] {message}";
                        txtChatBox.AppendText(timestampedMessage + Environment.NewLine);
                        txtChatBox.SelectionStart = txtChatBox.Text.Length;
                        txtChatBox.ScrollToCaret();
                    }
                }
            }
            catch
            {
                // Ignorar erros para prevenir travamentos
            }
        }

        // Enviar mensagem com assinatura digital
        private void buttonSend_Click(object sender, EventArgs e)
        {
            string msg = textBoxMessage.Text.Trim();
            if (string.IsNullOrWhiteSpace(msg))
                return;

            // Limpar campo de texto imediatamente
            textBoxMessage.Clear();

            // Enviar mensagem em background
            Task.Run(() =>
            {
                try
                {
                    if (networkStream != null && client != null && client.Connected)
                    {
                        // Criar assinatura digital da mensagem
                        string digitalSignature = CreateDigitalSignature(msg);
                        Console.WriteLine($"Mensagem assinada criada: {msg}");

                        // Formato da mensagem assinada
                        string signedMessageData = $"SIGNED_MESSAGE:{loggedUserId}:{loggedUsername}:{msg}:{digitalSignature}";

                        // Encriptar e enviar
                        string encryptedMessage = EncryptWithAES(signedMessageData);
                        byte[] packet = protocolSI.Make(ProtocolSICmdType.DATA, encryptedMessage);
                        networkStream.Write(packet, 0, packet.Length);

                        Console.WriteLine($"Mensagem enviada: {msg}");

                        // Mostrar mensagem enviada
                        UpdateChatBoxSafe($"Eu: {msg}");
                    }
                }
                catch (Exception ex)
                {
                    UpdateChatBoxSafe($"[ERRO] Falha ao enviar: {msg} - {ex.Message}");
                    Console.WriteLine($"Erro de envio: {ex.Message}");
                }
            });

            // Voltar foco para campo de texto
            textBoxMessage.Focus();
        }

        // Encriptar texto com AES
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

        // Desencriptar texto com AES
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

        // Fechar ligação do cliente
        private void CloseClient()
        {
            try
            {
                isRunning = false;

                // Fechar recursos de rede
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
                    catch { }

                    networkStream.Close();
                    networkStream = null;
                }

                if (client != null)
                {
                    client.Close();
                    client = null;
                }

                // Limpar chaves RSA
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

                // Aguardar fim da thread
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

        // Abrir nova janela de login
        private void btnAddUser_Click(object sender, EventArgs e)
        {
            try
            {
                // Criar nova janela de login numa thread separada
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
    }
}