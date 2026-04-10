using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Net.WebSockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web;
using System.Web.WebSockets;
using UtilDataPacket;

namespace WSP
{
    /// <summary>
    /// Модуль IIS для WebSocket прокси с поддержкой шифрования
    /// Активируется при наличии параметра proxy=1 в URL
    /// </summary>
    public class WebSocketProxyModule : IHttpModule
    {
        private const int SIZE_BUF = 63000;

        private class ConnectionTarget
        {
            public string Ip { get; set; }
            public int Port { get; set; }
        }

        private class ClientConnection
        {
            public WebSocket WebSocket { get; set; }
            public TcpClient TcpClient { get; set; }
            public ConnectionTarget Target { get; set; }
            public Task ReadingTask { get; set; }
        }

        // clientId (packet.UserId) → ClientConnection
        private static readonly ConcurrentDictionary<Guid, ClientConnection> _clients =
            new ConcurrentDictionary<Guid, ClientConnection>();

        // WebSocket → List<clientId> (для очистки при отключении)
        private static readonly ConcurrentDictionary<WebSocket, List<Guid>> _webSocketClients =
            new ConcurrentDictionary<WebSocket, List<Guid>>();

        // AES ключ per WebSocket connection
        private static readonly ConcurrentDictionary<WebSocket, byte[]> _aesKeys =
            new ConcurrentDictionary<WebSocket, byte[]>();

        // RSA провайдер для сервера (генерируется статически)
        private static readonly RSACryptoServiceProvider _rsaProvider;

        static WebSocketProxyModule()
        {
            _rsaProvider = new RSACryptoServiceProvider(2048);
        }

        public void Init(HttpApplication context)
        {
            context.PostAcquireRequestState += OnPostAcquireRequestState;
        }

        private void OnPostAcquireRequestState(object sender, EventArgs e)
        {
            var app = (HttpApplication)sender;
            var context = app.Context;

            string proxyParam = context.Request.QueryString["proxy"];

            if (proxyParam == "1")
            {
                if (context.IsWebSocketRequest)
                {
                    context.AcceptWebSocketRequest(ProcessWebSocket);
                    app.CompleteRequest();
                }
                else
                {
                    context.Response.ContentType = "text/plain";
                    context.Response.Write("!!!WebSocket Proxy Module Active. Use WebSocket protocol with ws:// or wss://");
                    context.Response.StatusCode = 200;
                    app.CompleteRequest();
                }
            }
        }

        private async Task ProcessWebSocket(AspNetWebSocketContext context)
        {
            WebSocket webSocket = context.WebSocket;
            List<Guid> clientIdsForThisSocket = new List<Guid>();

            _webSocketClients[webSocket] = clientIdsForThisSocket;
            _aesKeys[webSocket] = null;

            try
            {
                while (webSocket.State == WebSocketState.Open)
                {
                    try
                    {
                        byte[] buffer = new byte[SIZE_BUF];
                        using (var memoryStream = new MemoryStream())
                        {
                            WebSocketReceiveResult result;
                            do
                            {
                                result = await webSocket.ReceiveAsync(
                                    new ArraySegment<byte>(buffer),
                                    CancellationToken.None);

                                if (result.MessageType == WebSocketMessageType.Close)
                                    break;

                                memoryStream.Write(buffer, 0, result.Count);
                            }
                            while (!result.EndOfMessage && webSocket.State == WebSocketState.Open);

                            if (result.MessageType == WebSocketMessageType.Close)
                                break;

                            byte[] completeMessage = memoryStream.ToArray();

                            if (completeMessage.Length > 0)
                            {
                                byte[] aesKey = _aesKeys[webSocket];
                                DataPacket packet = DataPacket.Deserialize(completeMessage, aesKey);
                                await ProcessPacketAsync(webSocket, packet, clientIdsForThisSocket);
                            }
                        }
                    }
                    catch
                    {
                        break;
                    }
                }
            }
            finally
            {
                await CleanupWebSocketClients(webSocket, clientIdsForThisSocket);

                if (webSocket.State == WebSocketState.Open)
                {
                    try
                    {
                        await webSocket.CloseAsync(
                            WebSocketCloseStatus.NormalClosure,
                            "Closed",
                            CancellationToken.None);
                    }
                    catch { }
                }

                _webSocketClients.TryRemove(webSocket, out _);
                _aesKeys.TryRemove(webSocket, out _);
            }
        }

        private async Task ProcessPacketAsync(WebSocket webSocket, DataPacket packet, List<Guid> clientIdsForThisSocket)
        {
            byte[] aesKey = _aesKeys[webSocket];

            if (aesKey == null && packet.Type != MessageType.HandShakeRequest && packet.Type != MessageType.EncryptedSymmetricKey)
            {
                throw new InvalidOperationException("Handshake required before processing this message type");
            }

            try
            {
                switch (packet.Type)
                {
                    case MessageType.HandShakeRequest:
                        if (aesKey != null)
                            throw new InvalidOperationException("Handshake already completed");

                        string publicKeyXml = _rsaProvider.ToXmlString(false);
                        var pubKeyPacket = new DataPacket(Guid.Empty, MessageType.PublicKey,
                            Encoding.UTF8.GetBytes(publicKeyXml), "", 0);
                        byte[] pubSerialized = pubKeyPacket.Serialize(null);
                        await webSocket.SendAsync(new ArraySegment<byte>(pubSerialized),
                            WebSocketMessageType.Binary, true, CancellationToken.None);
                        break;

                    case MessageType.EncryptedSymmetricKey:
                        byte[] encryptedKey = packet.Data;
                        byte[] decryptedKey = _rsaProvider.Decrypt(encryptedKey, false);

                        if (decryptedKey.Length != 32)
                            throw new InvalidDataException("Invalid AES key length");

                        _aesKeys[webSocket] = decryptedKey;

                        var completePacket = new DataPacket(Guid.Empty, MessageType.HandShakeComplete,
                            Encoding.UTF8.GetBytes("OK"), "", 0);
                        byte[] completeSer = completePacket.Serialize(decryptedKey);
                        await webSocket.SendAsync(new ArraySegment<byte>(completeSer),
                            WebSocketMessageType.Binary, true, CancellationToken.None);
                        break;

                    case MessageType.Binary:
                        await ForwardToTcpServer(webSocket, packet, clientIdsForThisSocket);
                        break;

                    case MessageType.Error:
                        await ProcessError(webSocket, packet);
                        break;

                    case MessageType.Disconnect:
                        await ProcessDisconnect(packet.UserId, webSocket);
                        break;
                }
            }
            catch
            {
                await SendErrorResponse(webSocket, packet, new Exception("Error processing packet"));
            }
        }

        private async Task ForwardToTcpServer(WebSocket webSocket, DataPacket packet, List<Guid> clientIdsForThisSocket)
        {
            ClientConnection clientConn = GetOrCreateClientConnection(webSocket, packet, clientIdsForThisSocket);
            if (clientConn?.TcpClient == null) return;

            try
            {
                if (!clientConn.TcpClient.Connected)
                {
                    RemoveClient(packet.UserId, webSocket);
                    return;
                }

                NetworkStream stream = clientConn.TcpClient.GetStream();
                if (packet.Data?.Length > 0)
                {
                    await stream.WriteAsync(packet.Data, 0, packet.Data.Length);
                    await stream.FlushAsync();
                }
            }
            catch
            {
                RemoveClient(packet.UserId, webSocket);
            }
        }

        private async Task ReadFromTcpServer(Guid clientId, TcpClient tcpClient, WebSocket webSocket, ConnectionTarget target)
        {
            NetworkStream stream = null;
            try
            {
                stream = tcpClient.GetStream();
                byte[] buffer = new byte[SIZE_BUF];

                while (tcpClient.Connected && webSocket.State == WebSocketState.Open)
                {
                    int bytesRead;
                    try
                    {
                        bytesRead = await stream.ReadAsync(buffer, 0, SIZE_BUF);
                    }
                    catch
                    {
                        break;
                    }

                    if (bytesRead == 0) break;

                    byte[] receivedData = new byte[bytesRead];
                    Array.Copy(buffer, 0, receivedData, 0, bytesRead);

                    DataPacket responsePacket = new DataPacket(
                        clientId,
                        MessageType.Binary,
                        receivedData,
                        target.Ip,
                        target.Port
                    );

                    byte[] aesKey = _aesKeys[webSocket];
                    byte[] serialized = responsePacket.Serialize(aesKey);

                    try
                    {
                        if (webSocket.State == WebSocketState.Open)
                        {
                            await webSocket.SendAsync(
                                new ArraySegment<byte>(serialized),
                                WebSocketMessageType.Binary,
                                true,
                                CancellationToken.None
                            );
                        }
                        else
                        {
                            break;
                        }
                    }
                    catch
                    {
                        break;
                    }
                }
            }
            finally
            {
                RemoveClient(clientId, webSocket);
            }
        }

        private ClientConnection GetOrCreateClientConnection(WebSocket webSocket, DataPacket packet, List<Guid> clientIdsForThisSocket)
        {
            Guid clientId = packet.UserId;

            if (_clients.TryGetValue(clientId, out ClientConnection existingConn))
            {
                return existingConn;
            }

            TcpClient client = new TcpClient();
            try
            {
                client.Connect(packet.TargetIp, packet.TargetPort);

                ConnectionTarget target = new ConnectionTarget
                {
                    Ip = packet.TargetIp,
                    Port = packet.TargetPort
                };

                ClientConnection clientConn = new ClientConnection
                {
                    WebSocket = webSocket,
                    TcpClient = client,
                    Target = target
                };

                lock (clientIdsForThisSocket)
                {
                    clientIdsForThisSocket.Add(clientId);
                }

                if (_clients.TryAdd(clientId, clientConn))
                {
                    clientConn.ReadingTask = ReadFromTcpServer(clientId, client, webSocket, target);
                    return clientConn;
                }
                else
                {
                    client.Close();
                    client.Dispose();
                    return _clients.TryGetValue(clientId, out existingConn) ? existingConn : null;
                }
            }
            catch
            {
                lock (clientIdsForThisSocket)
                {
                    clientIdsForThisSocket.Remove(clientId);
                }
                client?.Close();
                client?.Dispose();
                throw;
            }
        }

        private async Task ProcessError(WebSocket webSocket, DataPacket packet)
        {
            await Task.CompletedTask;
        }

        private async Task ProcessDisconnect(Guid clientId, WebSocket webSocket)
        {
            _clients.TryGetValue(clientId, out ClientConnection clientConn);
            ConnectionTarget target = clientConn?.Target;
            byte[] aesKey = _aesKeys[webSocket];

            RemoveClient(clientId, webSocket);

            if (webSocket?.State == WebSocketState.Open && target != null)
            {
                try
                {
                    DataPacket response = new DataPacket(
                        clientId,
                        MessageType.Disconnect,
                        Encoding.UTF8.GetBytes("TCP connection closed successfully!!!"),
                        target.Ip,
                        target.Port
                    );

                    byte[] data = response.Serialize(aesKey);
                    if (webSocket.State == WebSocketState.Open)
                    {
                        await webSocket.SendAsync(
                            new ArraySegment<byte>(data),
                            WebSocketMessageType.Binary,
                            true,
                            CancellationToken.None);
                    }
                }
                catch { }
            }
        }

        private async Task SendErrorResponse(WebSocket webSocket, DataPacket packet, Exception ex)
        {
            if (webSocket?.State != WebSocketState.Open)
                return;

            try
            {
                DataPacket errorPacket = new DataPacket(
                    packet.UserId,
                    MessageType.Error,
                    Encoding.UTF8.GetBytes("Error: " + ex.Message),
                    packet.TargetIp,
                    packet.TargetPort
                );

                byte[] aesKey = _aesKeys[webSocket];
                byte[] data = errorPacket.Serialize(aesKey);

                if (webSocket.State == WebSocketState.Open)
                {
                    await webSocket.SendAsync(
                        new ArraySegment<byte>(data),
                        WebSocketMessageType.Binary,
                        true,
                        CancellationToken.None);
                }
            }
            catch { }
        }

        private async Task SendTcpDisconnectNotification(Guid clientId, WebSocket webSocket, ConnectionTarget target)
        {
            if (webSocket?.State != WebSocketState.Open)
                return;

            try
            {
                DataPacket packet = new DataPacket(
                    clientId,
                    MessageType.Disconnect,
                    Encoding.UTF8.GetBytes("TCP connection closed"),
                    target.Ip,
                    target.Port
                );

                byte[] aesKey = _aesKeys[webSocket];
                byte[] data = packet.Serialize(aesKey);

                if (webSocket.State == WebSocketState.Open)
                {
                    await webSocket.SendAsync(
                        new ArraySegment<byte>(data),
                        WebSocketMessageType.Binary,
                        true,
                        CancellationToken.None);
                }
            }
            catch { }
        }

        private void RemoveClient(Guid clientId, WebSocket webSocket)
        {
            if (_clients.TryRemove(clientId, out ClientConnection clientConn))
            {
                if (clientConn.WebSocket?.State == WebSocketState.Open)
                {
                    var ws = clientConn.WebSocket;
                    var target = clientConn.Target;

                    Task.Run(async () =>
                    {
                        try
                        {
                            await SendTcpDisconnectNotification(clientId, ws, target);
                        }
                        catch { }
                    });
                }

                try
                {
                    clientConn.TcpClient?.Close();
                    clientConn.TcpClient?.Dispose();
                }
                catch { }
            }
        }

        private async Task CleanupWebSocketClients(WebSocket webSocket, List<Guid> clientIds)
        {
            lock (clientIds)
            {
                foreach (Guid clientId in clientIds)
                {
                    RemoveClient(clientId, webSocket);
                }
                clientIds.Clear();
            }
            await Task.CompletedTask;
        }

        public void Dispose()
        {
            foreach (var kvp in _clients)
            {
                try
                {
                    kvp.Value.TcpClient?.Close();
                }
                catch { }
            }

            _clients.Clear();
            _webSocketClients.Clear();
            _aesKeys.Clear();
            _rsaProvider?.Dispose();
        }
    }
}
