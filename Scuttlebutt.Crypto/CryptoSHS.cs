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
    static class Utils
    {
        public static T[] Concat<T>(this T[] x, T[] y)
        {
            var oldLen = x.Length;
            Array.Resize<T>(ref x, x.Length + y.Length);
            Array.Copy(y, 0, x, oldLen, y.Length);
            return x;
        }
    }

    /// <summary>Handles the client protocol part of the SHS handshake</summary>
    public class Client
    {
        private const int SECTION_LENGTH = 32;
        private readonly byte[] _network_key;
        private KeyPair _ephemeral_client_keypair;
        private KeyPair _longterm_client_keypair;
        private byte[] _ephemeral_server_pk;
        private byte[] _shared_ab;
        private byte[] _shared_aB;

        /// <summary>Constructs the client given</summary>
        /// <param name="network_key">
        /// The key that identifies the network
        /// </param>
        Client(byte[] network_key)
        {
            this._network_key = network_key;
            _ephemeral_client_keypair = PublicKeyAuth.GenerateKeyPair();
        }

        /// <summary>
        /// Produces an ephemeral key and its signed version using the
        /// network key
        /// </summary>
        public byte[] Hello()
        {
            var signed_key = SecretKeyAuth.Sign(
                _ephemeral_client_keypair.PrivateKey,
                _network_key
            );

            var msg = new byte[SECTION_LENGTH * 2];

            return msg;
        }

        public Tuple<byte[], byte[]> Authenticate(
            byte[] server_pub_key,
            byte[] server_eph_key,
            byte[] long_term_pub_key,
            byte[] long_term_priv_key
        )
        {
            var a_b = ScalarMult.Mult(_ephemeral_client_keypair.PrivateKey, server_eph_key);
            var hash_a_b = CryptoHash.Hash(a_b);

            var to_hash = new byte[_network_key.Length + server_pub_key.Length + hash_a_b.Length];
                _network_key.CopyTo(to_hash, 0);
                server_pub_key.CopyTo(to_hash, _network_key.Length);
                hash_a_b.CopyTo(to_hash, server_pub_key.Length);

            var signed = PublicKeyAuth.SignDetached(to_hash, long_term_priv_key);
            var h = new byte[long_term_pub_key.Length + signed.Length];
                long_term_pub_key.CopyTo(h, 0);
                signed.CopyTo(h, long_term_pub_key.Length);

            var a_B = ScalarMult.Mult(_ephemeral_client_keypair.PrivateKey, server_pub_key);
            var A_b = ScalarMult.Mult(_ephemeral_client_keypair.PrivateKey, server_pub_key);

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

        private void DeriveSecrets()
        {
            var curve25519Sk = PublicKeyAuth
                .ConvertEd25519SecretKeyToCurve25519SecretKey(
                    this._longterm_client_keypair.PrivateKey
                );

            this._shared_ab = ScalarMult.Mult(
                this._ephemeral_client_keypair.PrivateKey,
                this._ephemeral_server_pk
            );

            this._shared_aB = ScalarMult.Mult(
                curve25519Sk,
                _ephemeral_server_pk
            );
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
                return _ephemeral_server_keypair.PublicKey;
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

        // Known network key
        private readonly byte[] _network_key;

        // Server keys
        private KeyPair _ephemeral_server_keypair;
        private KeyPair _longterm_server_keypair;

        // Client keys
        private byte[] _ephemeral_client_pk;
        private byte[] _longterm_client_pk;

        // Shared secrets
        private byte[] _shared_ab;
        private byte[] _shared_aB;
        private byte[] _shared_Ab;

        private byte[] detached_signature_A;

        /// <summary>
        ///   Constructs the server given the Network key and its keypair
        /// </summary>
        /// <param name="network_key">
        ///   The key that identifies the network
        /// </param>
        /// <param name="server_keypair">
        ///   The server's long term keypair
        /// </param>
        Server(byte[] network_key, KeyPair server_keypair)
        {
            this._network_key = network_key;
            this._longterm_server_keypair = server_keypair;
            _ephemeral_server_keypair = PublicKeyAuth.GenerateKeyPair();
        }

        /// <summary>
        ///   Validate client Hello
        /// </summary>
        /// <remark>
        ///   Here the server verifies that the received message length is 64
        ///   bytes, then extracts the client's ephemeral key and also verifies
        ///   that the hmac was signed with the network key.
        ///
        ///   This sets the object's <see cref="EphemeralClientKey"/>
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

            // Now that we have the client's ephemeral public key we can derive
            // the secret
            this.DeriveSecrets();
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

            var hmac = PublicKeyAuth.SignDetached(
                _ephemeral_server_keypair.PublicKey,
                _network_key
            );

            // Copy hmac into first 32 bytes of the msg
            Buffer.BlockCopy(
                hmac,
                0,
                msg,
                0,
                SECTION_LENGTH
            );
            // Copy server's ephemeral public key into last 32 bytes of the msg
            Buffer.BlockCopy(
                _ephemeral_server_keypair.PublicKey,
                0,
                msg,
                SECTION_LENGTH,
                SECTION_LENGTH
            );

            return msg;
        }

        /// <summary>
        ///   Checks for <paramref name="msg"/> length and validity, extracting
        ///   the client's long term public key upon success.
        /// </summary>
        /// <param name="msg">Client authenticate message</param>
        /// <exception cref="ArgumentException">
        ///   Thrown if the client Auth <paramref name="msg"/> fails to pass the
        ///   checks.
        /// </exception>
        public void AcceptAuth(byte[] msg)
        {
            var NONCE_SIZE = 24;

            if ( msg.Length != 112 ) {
                throw new ArgumentException("Incorrect secretbox length");
            }

            // A nonce consisting of 24 zeros
            var nonce = new byte[NONCE_SIZE];
            nonce.Initialize();

            // Concatenate the Network and derived keys
            var LEN = _network_key.Length +
                _shared_ab.Length +
                _shared_aB.Length;
            var to_hash = new byte[LEN];
            _network_key.CopyTo(to_hash, 0);
            _shared_ab.CopyTo(to_hash, _network_key.Length);
            _shared_aB.CopyTo(to_hash, _shared_ab.Length);

            // Calculate the decryption key from the dervided keys
            var key = CryptoHash.Sha256(to_hash);

            var opened_msg = SecretBox.Open(
                msg,
                nonce,
                key
            );

            if ( opened_msg.Length != 96 )
            {
                throw new ArgumentException("Invalid size of opened message");
            }

            // TODO: Extract signature size to const
            var SIG_SIZE = 64;
            var PUB_KEY_SIZE = 32;

            // Extract the signature of the long term client's public key
            // signed with the derived secret
            var detached_signature = new byte[SIG_SIZE];
            Buffer.BlockCopy(opened_msg, 0, detached_signature, 0, SIG_SIZE);

            // Extract the long term client's public key
            var lt_cli_pk = new byte[PUB_KEY_SIZE];
            Buffer.BlockCopy(opened_msg, SIG_SIZE, lt_cli_pk, 0, PUB_KEY_SIZE);

            var shared_hashed = CryptoHash.Sha256(_shared_ab);
            var VER_SIZE = _network_key.Length + _longterm_server_keypair.PublicKey.Length + shared_hashed.Length;
            // Concat network_key, server longterm pk and sha256 hashed shared_ab secret
            var to_verify = new byte[VER_SIZE];
            _network_key.CopyTo(to_verify, 0);
            _longterm_server_keypair.PublicKey.CopyTo(to_verify, _network_key.Length);
            shared_hashed.CopyTo(to_verify, _longterm_server_keypair.PublicKey.Length);

            if ( !SecretKeyAuth.Verify(to_verify, detached_signature, lt_cli_pk) )
            {
                throw new ArgumentException("Signature does not match");
            }

            _longterm_client_pk = lt_cli_pk;
            this.DeriveAb();
        }

        /// <summary>
        ///   Computes the message that accepts the handshake.
        /// </summary>
        /// <remark>
        ///   Here the server computes a signature of the network key, the
        ///   signature of the long term client's public key and a sha 256 of
        ///   the shared ab secret. This is signed with the server's long term
        ///   private key.
        ///
        ///   This signature is encrypted using a sha 256 of the network key
        ///   and all of the derived secrets.
        /// </remark>
        /// <returns>
        ///   A byte array of length 80 consisting of the message.
        /// </returns>
        public byte[] Accept()
        {
            var msg = new byte[80];
            var to_sign = new byte[0];
            var detached_signature = PublicKeyAuth.SignDetached(
                to_sign
                    .Concat(_network_key)
                    .Concat(detached_signature_A)
                    .Concat(_longterm_client_pk)
                    .Concat(
                        CryptoHash.Sha256(_shared_ab)
                    ),
                    _longterm_server_keypair.PublicKey
            );

            // A nonce consisting of 24 zeros
            var nonce = new byte[24];
            nonce.Initialize();

            var to_hash = new byte[0];

            SecretBox.CreateDetached(
                detached_signature,
                nonce,
                CryptoHash.Sha256(
                    to_hash
                        .Concat(_network_key)
                        .Concat(_shared_ab)
                        .Concat(_shared_aB)
                        .Concat(_shared_Ab)
                )
            );

            return msg;
        }

        private void DeriveSecrets()
        {
            var curve25519Sk = PublicKeyAuth
                .ConvertEd25519SecretKeyToCurve25519SecretKey(
                    this._longterm_server_keypair.PrivateKey
                );

            this._shared_ab = ScalarMult.Mult(
                this._ephemeral_server_keypair.PrivateKey,
                this._ephemeral_client_pk
            );

            this._shared_aB = ScalarMult.Mult(
                curve25519Sk,
                _ephemeral_client_pk
            );
        }

        private void DeriveAb()
        {
            var curve25519Sk = PublicKeyAuth
                .ConvertEd25519SecretKeyToCurve25519SecretKey(
                    this._longterm_client_pk
                );

            this._shared_Ab = ScalarMult.Mult(
                this._ephemeral_server_keypair.PublicKey,
                curve25519Sk
            );
        }
    }
}
