// Copyright © 2020 Pedro Gómez Martín <zentauro@riseup.net>
//
// This file is part of the library Scuttlebutt.Crypto which
// is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this library. If not, see <http://www.gnu.org/licenses/>.

using System;
using Sodium;

namespace Scuttlebutt.Crypto.SHS
{
    /// <summary>Handles the client protocol part of the SHS handshake</summary>
    public class Client
    {
        private readonly byte[] _network_key;
        private byte[] _ephemeral_client_key;

        /// <summary>Constructs the client given</summary>
        /// <param name="network_key">
        /// The key that identifies the network
        /// </param>
        Client(byte[] network_key)
        {
            this._network_key = network_key;
        }

        /// <summary>
        /// Produces an ephemeral key and its signed version using the
        /// network key
        /// </summary>
        public Tuple<byte[], byte[]> Hello()
        {
            _ephemeral_client_key = SecretKeyAuth.GenerateKey();
            var signed_key = SecretKeyAuth.Sign(_ephemeral_client_key, _network_key);

            return Tuple.Create(_ephemeral_client_key, signed_key);
        }

        public Tuple<byte[], byte[]> Authenticate(
            byte[] server_pub_key,
            byte[] server_eph_key,
            byte[] long_term_pub_key,
            byte[] long_term_priv_key
        )
        {
            var a_b = ScalarMult.Mult(_ephemeral_client_key, server_eph_key);
            var hash_a_b = CryptoHash.Hash(a_b);

            var to_hash = new byte[_network_key.Length + server_pub_key.Length + hash_a_b.Length];
                _network_key.CopyTo(to_hash, 0);
                server_pub_key.CopyTo(to_hash, _network_key.Length);
                hash_a_b.CopyTo(to_hash, server_pub_key.Length);

            var signed = PublicKeyAuth.SignDetached(to_hash, long_term_priv_key);
            var h = new byte[long_term_pub_key.Length + signed.Length];
                long_term_pub_key.CopyTo(h, 0);
                signed.CopyTo(h, long_term_pub_key.Length);

            var a_B = ScalarMult.Mult(_ephemeral_client_key, server_pub_key);
            var A_b = ScalarMult.Mult(_ephemeral_client_key, server_pub_key);

            var shared_secret = new byte[_network_key.Length + a_b.Length + a_B.Length + A_b.Length];
            var box_key = new byte[_network_key.Length + a_b.Length + a_B.Length];
                _network_key.CopyTo(box_key, 0);
                a_b.CopyTo(box_key, _network_key.Length);
                a_B.CopyTo(box_key, a_b.Length);
                box_key.CopyTo(shared_secret, 0);
                A_b.CopyTo(shared_secret, box_key.Length);

            var msg = SecretBox.Create(h, SecretBox.GenerateNonce(), box_key);
            return Tuple.Create(shared_secret, msg);
        }
    }

    public class Server
    {
        private readonly byte[] _network_key;
        private byte[] _ephemeral_server_key;

        /// <summary>Constructs the server given</summary>
        /// <param name="network_key">
        /// The key that identifies the network
        /// </param>
        Server(byte[] network_key)
        {
            this._network_key = network_key;
        }

        /// <summary>
        ///   The response to a client hello
        /// </summary>
        public byte[] AcceptHello(byte[] msg)
        {
            var client_key_length = msg.Length - 256/8;
            var ephemeral_client_key = new byte[client_key_length];
            Buffer.BlockCopy(msg, 0, ephemeral_client_key, 0, client_key_length);
            return ephemeral_client_key;
        }

        public Tuple<byte[], byte[]> Hello(byte[] ephemeral_client_key)
        {
            _ephemeral_server_key = SecretKeyAuth.GenerateKey();
            var signing_key = ScalarMult.Mult(ephemeral_client_key, _ephemeral_server_key);
            var signed_key = SecretKeyAuth.Sign(_ephemeral_server_key, signing_key);

            return Tuple.Create(_ephemeral_server_key, signed_key);
        }

        public byte[] Authenticate()
        {
            return new byte[8];
        }
    }
}
