# Tunna 2.0

## Brief Description

Tunna 2.0 is a secure TCP tunneling solution that enables communication between TCP clients and servers through WebSocket connections. The project consists of two main components:

- **TcpToWebSocketProxy** — A .NET console application that listens on one or multiple TCP ports and forwards data through WebSocket to a web server.
- **IISProxyServer** — A web wrapper (ASPX) for receiving WebSocket connections on the server side (used as a message receiver and gateway to target TCP services on the server side).

## Security Features

### End-to-End Encryption

Tunna 2.0 implements a robust security model using hybrid encryption:

1. **RSA Handshake**: Initial key exchange using RSA-2048 asymmetric encryption
2. **AES-256 Encryption**: Symmetric encryption for all subsequent data transmission
3. **HMAC-SHA256**: Message integrity verification

#### Handshake Process:
1. Client sends `HandShakeRequest` to initiate secure connection
2. Server responds with RSA public key (`PublicKey` message)
3. Client generates random AES-256 key, encrypts it with server's RSA public key, and sends it (`EncryptedSymmetricKey`)
4. Server decrypts AES key and confirms handshake completion (`HandShakeComplete`)
5. All subsequent communication is encrypted with the negotiated AES key

#### Encryption Details:
- **Symmetric Algorithm**: AES-256 in CBC mode with PKCS7 padding
- **Key Derivation**: Random 256-bit keys generated per session
- **Integrity**: HMAC-SHA256 for message authentication

## Data Transmission Architecture

```
+------------+       +---------------------+       +-------------------+       +---------------------+
| TCP Client | <---> | TcpToWebSocketProxy | <---> |   WebSocket/IIS   | <---> | Target TCP Service  |
+------------+       +---------------------+       +-------------------+       +---------------------+
```

## Configuration

The configuration file must be located next to the executable file.

### Example Configuration:

```json
{
  "webSocketUrl": "ws://localhost/IIS/main.aspx",
  "tcpBufferSize": 65400,
  "webSocketBufferSize": 65400,
  "maxWebSocketMessageSize": 1048576,
  "portMappings": [
    {
      "listenPort": 1111,
      "targetIp": "192.168.72.1",
      "targetPort": 1433
    },
    {
      "listenPort": 2222,
      "targetIp": "192.168.181.131",
      "targetPort": 22
    },
    {
      "listenPort": 11111,
      "targetIp": "127.0.0.1",
      "targetPort": 12345
    }
  ]
}
```

### Configuration Parameters:
- `webSocketUrl`: WebSocket endpoint URL for IIS proxy server
- `tcpBufferSize`: Buffer size for TCP data transmission (default: 65400 bytes)
- `webSocketBufferSize`: Buffer size for WebSocket communication (default: 65400 bytes)
- `maxWebSocketMessageSize`: Maximum allowed WebSocket message size (default: 1MB)
- `portMappings`: Array of port forwarding rules

## Quick Start Guide

### Requirements:
- .NET SDK/Runtime (Target Framework: net8.0)

### Running from Source (Recommended for Debugging):

1. Open command line in the `TcpToWebSocketProxy` folder.
2. Optionally modify `proxyconfig.json` (e.g., `webSocketUrl` and port mappings).
3. Run the application via `dotnet run` or build and run the executable:

```cmd
cd TcpToWebSocketProxy
dotnet run --project TcpToWebSocketProxy.csproj
```

You can also specify an alternative configuration file path at startup:

```cmd
dotnet run --project TcpToWebSocketProxy.csproj -- "C:\path\to\your\proxyconfig.json"
```

After successful startup, the console will display information about WebSocket URL, buffer sizes, and the list of ports.
Press `Q` in the console to gracefully stop the server.

## IIS Proxy Server Deployment

The `IISProxyServer` is a simple web page/endpoint (ASPX). Deploy the contents of the `IISProxyServer` folder to an IIS application (or virtual directory of your web server). Ensure that WebSocket support is enabled and active in IIS (Windows feature).

### IIS Module Implementation

The project now also includes an IIS module-based server implementation in `IISProxyServer/ModuleDLL`.

- `module.cs` contains an `IHttpModule` implementation that can handle proxy traffic through IIS pipeline events.
- `DataPacket.cs` mirrors the packet format used by the client proxy component.
- `ModuleDLL.csproj` targets .NET Framework for IIS module deployment.

This module option can be used as an alternative to the ASPX endpoint when deeper IIS pipeline integration is required.

#### Module Deployment Notes:
- Build `ModuleDLL` in Release mode.
- Copy the output DLL to the IIS application `bin` folder (or GAC if your deployment model requires it).
- Register the module in `web.config` under IIS modules configuration.
- Ensure the application pool has required permissions and WebSocket support is enabled.

### IIS Requirements:
- WebSocket Protocol enabled
- ASP.NET support
- Appropriate permissions for the application pool

## Use Cases

- **Database Access**: Secure remote access to databases through firewalls
- **SSH Tunneling**: Encrypted SSH connections through WebSocket
- **Legacy System Integration**: Access to systems behind restrictive firewalls
- **Development Environments**: Secure access to development servers

## Security Considerations

- All data transmission is encrypted end-to-end
- Per-session encryption keys prevent key reuse attacks
- RSA handshake ensures secure key exchange
- HMAC verification prevents message tampering
- Handshake requirement prevents unauthorized connections

## Troubleshooting

- Ensure WebSocket feature is enabled in IIS
- Verify firewall settings allow WebSocket connections
- Check that target TCP services are accessible from IIS server