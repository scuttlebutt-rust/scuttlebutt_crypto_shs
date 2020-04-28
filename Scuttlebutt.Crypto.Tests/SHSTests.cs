using System;
using Xunit;
using Scuttlebutt.Crypto.SHS;
using Sodium;

namespace Scuttlebutt.Crypto.Tests
{
    public class SHSClientTests
    {
        [Fact]
        public void ItBuilds()
        {
            var network_key = new byte[] {
                0xd4, 0xa1, 0xcb, 0x88, 0xa6, 0x6f, 0x02, 0xf8, 0xdb, 0x63, 0x5c,
                0xe2, 0x64, 0x41, 0xcc, 0x5d, 0xac, 0x1b, 0x08, 0x42, 0x0c, 0xea,
                0xac, 0x23, 0x08, 0x39, 0xb7, 0x55, 0x84, 0x5a, 0x9f, 0xfb
            };
            var client_keypair = PublicKeyAuth.GenerateKeyPair();
            var server_keypair = PublicKeyAuth.GenerateKeyPair();
            var client = new Client(network_key, server_keypair.PublicKey, client_keypair);
        }
    }
    public class SHSIntegrationTest
    {
        [Fact]
        public void ItWorks()
        {
            var network_key = new byte[] {
                0xd4, 0xa1, 0xcb, 0x88, 0xa6, 0x6f, 0x02, 0xf8, 0xdb, 0x63, 0x5c,
                0xe2, 0x64, 0x41, 0xcc, 0x5d, 0xac, 0x1b, 0x08, 0x42, 0x0c, 0xea,
                0xac, 0x23, 0x08, 0x39, 0xb7, 0x55, 0x84, 0x5a, 0x9f, 0xfb
            };

            var client_keypair = PublicKeyAuth.GenerateKeyPair();
            var server_keypair = PublicKeyAuth.GenerateKeyPair();

            var client = new Client(network_key, server_keypair.PublicKey, client_keypair);
            var server = new Server(network_key, server_keypair);

            // Client -> Server [1]
            var client_hello = client.Hello();
            server.AcceptHello(client_hello);

            // Client <- Server [2]
            var server_hello = server.Hello();
            client.AcceptHello(server_hello);

            // Client -> Server [3]
            var client_auth = client.Authenticate();
            server.AcceptAuth(client_auth);

            // Client <- Server [4]
            var server_accept = server.Accept();
            client.VerifyAccept(server_accept);

            client.ClientDerivedSecret.Equals(server.ClientDerivedSecret);
            client.ServerDerivedSecret.Equals(server.ServerDerivedSecret);
            client.EphemeralDerivedSecret.Equals(server.EphemeralDerivedSecret);
        }
    }
}
