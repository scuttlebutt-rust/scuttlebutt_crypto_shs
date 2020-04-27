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
        /// <summary>
        ///   The server's epehemeral key
        /// </summary>
        public byte[] EphemeralServerKey
        {
            get
            {
                return _ephemeral_server_pk;
            }
        }
        /// <summary>
        ///   The client's epehemeral key
        /// </summary>
        public byte[] EphemeralClientKey
        {
            get
            {
                return _ephemeral_client_pk;
            }
        }

        private const int SECTION_LENGTH = 32;
        private readonly byte[] _network_key;
        private byte[] _ephemeral_server_pk;
        private byte[] _ephemeral_client_pk;

        /// <summary>Constructs the server given</summary>
        /// <param name="network_key">
        /// The key that identifies the network
        /// </param>
        Server(byte[] network_key)
        {
            this._network_key = network_key;
            _ephemeral_server_pk = SecretKeyAuth.GenerateKey();
        }

        /// <summary>
        ///   Validate client Hello
        /// </summary>
        /// <remark>
        ///   Here the server verifies that the received message length is 64
        ///   bytes, then extracts the client's ephemeral key and also verifies
        ///   that the hmac was signed with the network key.
        ///
        ///   This sets the object's <see cref="">_client_ephemeral_key</see>
        /// </remark>
        /// <exception cref="ArgumentException">
        ///   Thrown if the client Hello <paramref name="msg"/> fails to pass the
        ///   checks.
        /// </exception>
        /// <param name="msg">
        ///   The received message, the first 32 bytes correspond to the client
        ///   ephemeral key and the last 32 bytes to the hmac.
        /// </param>
        public void AcceptHello(byte[] msg)
        {
            if (msg.Length != 64)
            {
                throw new ArgumentException("The received message is not 64 bytes");
            }

            // Separate the message in ephemeral key and hmac
            var ephemeral_client_key = new byte[SECTION_LENGTH];
            Buffer.BlockCopy(msg, 0, ephemeral_client_key, 0, SECTION_LENGTH);
            var hmac = new byte[SECTION_LENGTH];
            Buffer.BlockCopy(msg, 0, hmac, 0, SECTION_LENGTH);

            // Check if the key used to sign the hmac of the ephemeral_client_key is
            // valid
            //
            // Aka, check if we are in the same network
            if (!SecretKeyAuth.Verify(ephemeral_client_key, hmac, _network_key))
            {
                throw new ArgumentException("The hmac does not match");
            }
            else
            {
                this._ephemeral_client_pk = ephemeral_client_key;
            }
        }

        /// <summary>
        ///   Craft server response to client hello
        /// </summary>
        /// <returns>
        ///   Returns the message ready to be sent, consisting of the server
        ///   ephemeral key and an hmac of the server key signed with the
        ///   network key.
        /// </returns>
        public byte[] Hello()
        {
            var msg = new byte[SECTION_LENGTH * 2];

        }

        /// <summary>
        ///   Accepts
        /// </summary>
        public Tuple<byte[], byte[]> Accept(byte[] ephemeral_client_key)
        {
            var signing_key = ScalarMult.Mult(ephemeral_client_key, _ephemeral_server_pk);
            var signed_key = SecretKeyAuth.Sign(_ephemeral_server_pk, signing_key);

            return Tuple.Create(_ephemeral_server_pk, signed_key);
        }

        public byte[] Authenticate()
        {
            return new byte[8];
        }
    }
}
