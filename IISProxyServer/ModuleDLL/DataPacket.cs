using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace UtilDataPacket
{
    public enum MessageType : int
    {
        Text = 1,
        Binary = 2,
        File = 3,
        Error = 4,
        Disconnect = 5,
        HandShakeRequest = 10,
        PublicKey = 11,
        EncryptedSymmetricKey = 12,
        HandShakeComplete = 13
    }

    public enum IpAddressType : byte
    {
        None = 0,
        IPv4 = 1,
        IPv6 = 2
    }

    internal class IpParseResult
    {
        public IpAddressType Type { get; set; }
        public byte[] Bytes { get; set; }

        public IpParseResult(IpAddressType type, byte[] bytes)
        {
            Type = type;
            Bytes = bytes;
        }
    }

    [Serializable]
    public class DataPacket
    {
        private const uint MAGIC_NUMBER = 0xDEADBEEF;

        public Guid UserId { get; set; }
        public MessageType Type { get; set; }
        public byte[] Data { get; set; }
        public string TargetIp { get; set; }
        public int TargetPort { get; set; }

        public DataPacket() { }

        public DataPacket(Guid userId, MessageType type, byte[] data, string targetIp, int targetPort) : this()
        {
            UserId = userId;
            Type = type;
            TargetIp = targetIp;
            TargetPort = targetPort;
            Data = data;
        }

        public DataPacket(Guid userId, MessageType type, string text, string targetIp, int targetPort)
            : this(userId, type, Encoding.UTF8.GetBytes(text), targetIp, targetPort)
        {
        }

        private IpParseResult ParseIpAddress(string ip)
        {
            if (string.IsNullOrEmpty(ip))
                return new IpParseResult(IpAddressType.None, new byte[0]);

            if (IPAddress.TryParse(ip, out IPAddress address))
            {
                if (address.AddressFamily == AddressFamily.InterNetwork)
                {
                    return new IpParseResult(IpAddressType.IPv4, address.GetAddressBytes());
                }
                else if (address.AddressFamily == AddressFamily.InterNetworkV6)
                {
                    return new IpParseResult(IpAddressType.IPv6, address.GetAddressBytes());
                }
            }

            throw new ArgumentException("Invalid IP address format: " + ip);
        }

        public byte[] Serialize(byte[] encryptionKey)
        {
            using (var ms = new MemoryStream())
            using (var writer = new BinaryWriter(ms))
            {
                writer.Write(MAGIC_NUMBER);
                writer.Write(UserId.ToByteArray());
                writer.Write((int)Type);

                var ipParseResult = ParseIpAddress(TargetIp);
                writer.Write((byte)ipParseResult.Type);

                if (ipParseResult.Type != IpAddressType.None && ipParseResult.Bytes.Length > 0)
                {
                    writer.Write(ipParseResult.Bytes);
                }

                writer.Write(TargetPort);
                writer.Write(Data?.Length ?? 0);

                if (Data != null && Data.Length > 0)
                    writer.Write(Data);

                var plainPacket = ms.ToArray();

                return encryptionKey == null ? plainPacket : EncryptPacket(plainPacket, encryptionKey);
            }
        }

        public static DataPacket Deserialize(byte[] data, byte[] encryptionKey)
        {
            if (data == null || data.Length < 33)
                throw new InvalidDataException("Packet too short or null");

            byte[] decrypted = encryptionKey == null ? data : DecryptPacket(data, encryptionKey);

            using (var ms = new MemoryStream(decrypted))
            using (var reader = new BinaryReader(ms))
            {
                var magic = reader.ReadUInt32();
                if (magic != MAGIC_NUMBER)
                    throw new InvalidDataException("Invalid packet format");

                var guidBytes = reader.ReadBytes(16);
                var userId = new Guid(guidBytes);
                var type = (MessageType)reader.ReadInt32();
                var ipType = (IpAddressType)reader.ReadByte();

                string targetIp = null;
                byte[] ipBytes = null;

                switch (ipType)
                {
                    case IpAddressType.IPv4:
                        ipBytes = reader.ReadBytes(4);
                        break;
                    case IpAddressType.IPv6:
                        ipBytes = reader.ReadBytes(16);
                        break;
                    case IpAddressType.None:
                        break;
                    default:
                        throw new InvalidDataException("Unknown IP address type: " + ipType);
                }

                if (ipBytes != null && ipBytes.Length > 0)
                {
                    targetIp = new IPAddress(ipBytes).ToString();
                }

                var targetPort = reader.ReadInt32();
                var dataLength = reader.ReadInt32();
                byte[] packetData = dataLength > 0 ? reader.ReadBytes(dataLength) : null;

                return new DataPacket
                {
                    UserId = userId,
                    Type = type,
                    TargetIp = targetIp,
                    TargetPort = targetPort,
                    Data = packetData,
                };
            }
        }

        public string GetDataAsString()
        {
            return Data != null ? Encoding.UTF8.GetString(Data) : null;
        }

        private static byte[] EncryptPacket(byte[] plainPacket, byte[] key)
        {
            if (plainPacket == null) throw new ArgumentNullException(nameof(plainPacket));
            if (key == null || key.Length != 32) throw new ArgumentException("Invalid encryption key");

            using (var aes = Aes.Create())
            using (var hmac = new HMACSHA256(key))
            {
                aes.Key = key;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;
                aes.GenerateIV();

                using (var encryptor = aes.CreateEncryptor())
                {
                    byte[] cipher = encryptor.TransformFinalBlock(plainPacket, 0, plainPacket.Length);
                    byte[] iv = aes.IV;

                    byte[] hmacData = Combine(iv, cipher);
                    byte[] tag = hmac.ComputeHash(hmacData);

                    byte[] result = new byte[1 + iv.Length + cipher.Length + tag.Length];
                    result[0] = (byte)iv.Length;
                    Array.Copy(iv, 0, result, 1, iv.Length);
                    Array.Copy(cipher, 0, result, 1 + iv.Length, cipher.Length);
                    Array.Copy(tag, 0, result, 1 + iv.Length + cipher.Length, tag.Length);

                    return result;
                }
            }
        }

        private static byte[] DecryptPacket(byte[] encryptedPacket, byte[] key)
        {
            if (encryptedPacket == null || encryptedPacket.Length < 1 + 16 + 32)
                throw new InvalidDataException("Encrypted packet too short");
            if (key == null || key.Length != 32) throw new ArgumentException("Invalid encryption key");

            int ivLength = encryptedPacket[0];
            if (ivLength <= 0 || encryptedPacket.Length < 1 + ivLength + 32)
                throw new InvalidDataException("Invalid IV length in encrypted packet");

            int cipherLength = encryptedPacket.Length - 1 - ivLength - 32;
            if (cipherLength <= 0)
                throw new InvalidDataException("Encrypted packet has no cipher data");

            byte[] iv = new byte[ivLength];
            Array.Copy(encryptedPacket, 1, iv, 0, ivLength);

            byte[] cipher = new byte[cipherLength];
            Array.Copy(encryptedPacket, 1 + ivLength, cipher, 0, cipherLength);

            byte[] tag = new byte[32];
            Array.Copy(encryptedPacket, 1 + ivLength + cipherLength, tag, 0, 32);

            using (var hmac = new HMACSHA256(key))
            {
                byte[] expectedTag = hmac.ComputeHash(Combine(iv, cipher));
                if (!expectedTag.SequenceEqual(tag))
                    throw new InvalidDataException("Encrypted packet HMAC mismatch");
            }

            using (var aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                using (var decryptor = aes.CreateDecryptor())
                {
                    return decryptor.TransformFinalBlock(cipher, 0, cipher.Length);
                }
            }
        }

        private static byte[] Combine(params byte[][] buffers)
        {
            int total = buffers.Where(b => b != null).Sum(b => b.Length);
            byte[] result = new byte[total];
            int offset = 0;

            foreach (var buffer in buffers.Where(b => b != null))
            {
                Array.Copy(buffer, 0, result, offset, buffer.Length);
                offset += buffer.Length;
            }

            return result;
        }
    }
}