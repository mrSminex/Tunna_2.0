using System;
using System.Buffers;
using System.Net.WebSockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using TcpToWebSocketProxy;
using UtilDataPacket;
// Я внес изменения в следующие классы:
// - WebSocketConnection: Добавил логику handshake в ConnectAsync, используя новый метод HandshakeAsync.
//   Теперь подключение включает обмен ключами перед запуском основного receive loop.
//   Добавил поле _aesKey для хранения динамического AES ключа.
//   В SendAsync и ReceiveMessagesAsync используется _aesKey после handshake.
// - DataPacket: Убрал статический ключ, сделал Serialize/Deserialize принимать byte[] encryptionKey.
//   EncryptPacket/DecryptPacket теперь принимают key как параметр.
//   Если encryptionKey == null, не шифруется (для handshake).
// - MessageType: Добавил новые типы для handshake.
namespace TcpToWebSocketProxy
{
    public class WebSocketConnection
    {
        private readonly string _url;
        private readonly ClientManager _clientManager;
        private readonly int _webSocketBufferSize;
        private readonly int _maxMessageSize;
        private ClientWebSocket _webSocket;
        private readonly object _lock = new object();
        private ArrayPool<byte> arrayPool = ArrayPool<byte>.Shared;

        private byte[] _aesKey = null; // Динамический AES ключ после handshake


        public WebSocketConnection(string url, ClientManager clientManager, int webSocketBufferSize, int maxMessageSize)
        {
            _url = url;
            _clientManager = clientManager;
            _webSocketBufferSize = webSocketBufferSize;
            _maxMessageSize = maxMessageSize;
        }

        public async Task ConnectAsync()
        {
            lock (_lock)
            {
                _webSocket = new ClientWebSocket();
            }

            await _webSocket.ConnectAsync(new Uri(_url), CancellationToken.None);

            // Выполняем handshake перед запуском receive
            await HandshakeAsync();

            _ = Task.Run(ReceiveMessagesAsync);
        }
        // Новый метод: Выполняет handshake для обмена ключами
        private async Task HandshakeAsync()
        {
            Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] Starting handshake...");

            // Шаг 1: Отправляем запрос на публичный ключ (без шифрования)
            var requestPacket = new DataPacket(Guid.Empty, MessageType.HandShakeRequest, (byte[])null, "", 0);
            await SendAsync(requestPacket, CancellationToken.None); // Serialize(null)

            // Шаг 2: Получаем публичный ключ от сервера (без шифрования)
            byte[] pubKeyData = await ReceiveOneMessageAsync();
            var pubKeyPacket = DataPacket.Deserialize(pubKeyData, null);
            if (pubKeyPacket.Type != MessageType.PublicKey)
            {
                throw new InvalidOperationException("Expected PublicKey response");
            }
            string publicKeyXml = Encoding.UTF8.GetString(pubKeyPacket.Data);

            // Шаг 3: Генерируем AES ключ, шифруем его RSA публичным ключом и отправляем (без шифрования)
            using (var rsa = new RSACryptoServiceProvider())
            {
                rsa.FromXmlString(publicKeyXml);
                byte[] aesKey = new byte[32]; // 256-bit AES ключ
                using (var rng = new RNGCryptoServiceProvider())
                {
                    rng.GetBytes(aesKey);
                }
                byte[] encryptedAesKey = rsa.Encrypt(aesKey, false); // RSA_PKCS1_PADDING
                var keyPacket = new DataPacket(Guid.Empty, MessageType.EncryptedSymmetricKey, encryptedAesKey, "", 0);
                await SendAsync(keyPacket, CancellationToken.None); // Serialize(null)

                // Оптимистично устанавливаем _aesKey
                _aesKey = aesKey;
            }

            // Шаг 4: Получаем подтверждение (уже зашифрованное новым AES ключом)
            byte[] completeData = await ReceiveOneMessageAsync();
            var completePacket = DataPacket.Deserialize(completeData, _aesKey);
            if (completePacket.Type != MessageType.HandShakeComplete || completePacket.GetDataAsString() != "OK")
            {
                throw new InvalidOperationException("Handshake completion failed");
            }

            Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] Handshake complete. Using AES encryption !!!");
        }

        // Вспомогательный метод: Получает одно полное сообщение (аналогично ReceiveMessagesAsync, но для одного сообщения)
        private async Task<byte[]> ReceiveOneMessageAsync()
        {
            int initialBufferSize = _webSocketBufferSize;
            var buffer = arrayPool.Rent(initialBufferSize);
            try
            {
                using (var memoryStream = new MemoryStream())
                {
                    WebSocketReceiveResult result;
                    do
                    {
                        result = await _webSocket.ReceiveAsync(new ArraySegment<byte>(buffer), CancellationToken.None);
                        if (result.MessageType == WebSocketMessageType.Close)
                            throw new InvalidOperationException("WebSocket closed during receive");
                        memoryStream.Write(buffer, 0, result.Count);
                    }
                    while (!result.EndOfMessage && _webSocket.State == WebSocketState.Open);
                    return memoryStream.ToArray();
                }
            }
            finally
            {
                arrayPool.Return(buffer);
            }
        }
        public async Task SendAsync(DataPacket packet, CancellationToken ct)
        {
            
            try
            {
                if (_webSocket?.State != WebSocketState.Open)
                    throw new InvalidOperationException("WebSocket is not connected");
                // Используем _aesKey, если установлен (после handshake), иначе null
                byte[] encryptionKey = _aesKey; // Во время handshake вызывается с null вручную
                var data = packet.Serialize(encryptionKey);

                // Проверка размера сообщения
                if (data.Length > _maxMessageSize)
                {
                    throw new InvalidOperationException($"Message size {data.Length} exceeds maximum allowed {_maxMessageSize}");
                }

                await _webSocket.SendAsync(
                    new ArraySegment<byte>(data),
                    WebSocketMessageType.Binary,
                    true, // endOfMessage = true - мы всегда отправляем полные сообщения!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
                    //но если мы отправляем кусок то конец же не нужен
                    ct
                );
            }
            finally
            {
               
            }
        }
        public async Task SendDisconnectPacketAsync(Guid clientId, string targetIp, int targetPort)
        {
            if (_webSocket?.State != WebSocketState.Open)
                return;

            try
            {
                var disconnectPacket = new DataPacket(
                    clientId,
                    MessageType.Disconnect,
                    Encoding.UTF8.GetBytes("Client disconnected"),
                    targetIp,
                    targetPort
                );

                await SendAsync(disconnectPacket, CancellationToken.None);
                Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] *** Disconnect packet sent for client: {clientId}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] *** Error sending disconnect packet for client {clientId}: {ex.Message}");
            }
        }
        //----------------------------------------------------------
        private async Task ReceiveMessagesAsync()
        {
            int initialBufferSize = _webSocketBufferSize;
            while (_webSocket?.State == WebSocketState.Open)
            {
                //var buffer = ArrayPool<byte>.Shared.Rent(initialBufferSize); 
                var buffer = arrayPool.Rent(initialBufferSize);
                try
                {
                    using (var memoryStream = new MemoryStream())
                    {
                        WebSocketReceiveResult result;
                        do
                        {
                            result = await _webSocket.ReceiveAsync(
                                new ArraySegment<byte>(buffer),
                                CancellationToken.None);

                            if (result.MessageType == WebSocketMessageType.Close)
                                break;

                            memoryStream.Write(buffer, 0, result.Count);
                        }
                        while (!result.EndOfMessage && _webSocket.State == WebSocketState.Open);

                        if (result.MessageType == WebSocketMessageType.Close)
                            break;

                        var completeMessage = memoryStream.ToArray();

                        if (completeMessage.Length > 0)
                        {
                            await ProcessReceivedMessage(completeMessage);
                        }
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"*** (ReceiveMessagesAsync) WebSocket receive error: {ex.Message}");
                    break;
                }
                finally
                {
                    ArrayPool<byte>.Shared.Return(buffer);
                }
            }
        }
        private async Task ProcessReceivedMessage(byte[] messageData)
        {
            try
            {
                var packet = DataPacket.Deserialize(messageData, _aesKey);

                if (_clientManager.TryGetClient(packet.UserId, out var client))
                {
                    await client.ForwardToTcpAsync(packet.Data);
                }
                else
                {
                    Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] *** (ProcessReceivedMessage) Unknown client ID: {packet.UserId}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] *** Error processing received message: {ex.Message}");
            }
        }
        public async Task DisconnectAsync()
        {
            if (_webSocket?.State == WebSocketState.Open)
            {
                await _webSocket.CloseAsync(
                    WebSocketCloseStatus.NormalClosure,
                    "Closing",
                    CancellationToken.None);
            }
        }
    }
}