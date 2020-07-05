# A Secret Handshake implementation

This library implements the secret handshake as specified in the secure
scuttlebutt [protocol guide](https://ssbc.github.io/scuttlebutt-protocol-guide/#handshake).
Its only dependency is libsodium-core.

## Intended usage

To see a complete example, check out the self integration
[test](https://github.com/radio-patio/scuttlebutt_crypto_shs/blob/master/Scuttlebutt.Crypto.SHS.Tests/SHSTests.cs).

```cs
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
```
