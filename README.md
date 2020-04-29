# Description
This is an implementation of the Secret Handshake protocol as described in the
[https://ssbc.github.io/scuttlebutt-protocol-guide/#handshake](scuttlebutt protocol guide)

# Sample usage
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
