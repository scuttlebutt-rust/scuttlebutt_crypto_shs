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
    /// <summary>
    ///   Handles the server side of the SHS handshake
    /// </summary>
    public class Server
    {
        /// <summary>
        ///   The secret derived from the ephemeral keys (ab).
        /// </summary>
        public byte[] EphemeralDerivedSecret
        {
            get { return _shared_ab; }
        }
        /// <summary>
        ///   The secret derived from the client ephemeral key and the server's
        ///   long term key (aB).
        /// </summary>
        public byte[] ServerDerivedSecret
        {
            get { return _shared_aB; }
        }
        /// <summary>
        ///   The secret derived from the client long term key and the server's
        ///   ephemeral key (Ab).
        /// </summary>
        public byte[] ClientDerivedSecret
        {
            get { return _shared_Ab; }
        }

        // Constants
        private const int SECTION_LENGTH = 32;
        private const int SIG_SIZE = 64;
        private const int PUB_KEY_SIZE = 32;
        private const int NONCE_SIZE = 24;

        // Known network key
        private readonly byte[] _network_key;

        // Server keys
        readonly private SHS.KeyPair _ephemeral_server_keypair;
        readonly private Sodium.KeyPair _longterm_server_keypair;

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
        public Server(byte[] network_key, Sodium.KeyPair server_keypair)
        {
            this._network_key = network_key;
            this._longterm_server_keypair = server_keypair;

            _ephemeral_server_keypair = new KeyPair(PublicKeyAuth.GenerateKeyPair());
        }

        /// <summary>
        ///   Validate client Hello
        /// </summary>
        /// <remark>
        ///   Here the server verifies that the received message length is 64
        ///   bytes, then extracts the client's ephemeral key and also verifies
        ///   that the hmac was signed with the network key.
        ///
        ///   This sets the object's <see cref="_ephemeral_client_pk"/>
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
            Buffer.BlockCopy(msg, SECTION_LENGTH, ephemeral_client_key, 0, SECTION_LENGTH);
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
            // the first 2 secrets
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
            var hmac = SecretKeyAuth.Sign(
                _ephemeral_server_keypair.PublicKey,
                _network_key
            );

            var msg = Utils.Concat(
                hmac, _ephemeral_server_keypair.PublicKey
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

            if ( msg.Length != 112 ) {
                throw new ArgumentException("Incorrect secretbox length");
            }

            // A nonce consisting of 24 zeros
            var nonce = new byte[NONCE_SIZE];
            nonce.Initialize();

            // Calculate the decryption key from the dervided keys
            var key = CryptoHash.Sha256(
                Utils.Concat(_network_key, _shared_ab, _shared_aB)
            );

            var opened_msg = SecretBox.Open(msg, nonce, key);

            if ( opened_msg.Length != 96 )
            {
                throw new ArgumentException("Invalid size of opened message");
            }

            // Extract the signature of the long term client's public key
            // signed with the derived secret
            var detached_signature = new byte[SIG_SIZE];
            Buffer.BlockCopy(opened_msg, 0, detached_signature, 0, SIG_SIZE);

            // Extract the long term client's public key
            var lt_cli_pk = new byte[PUB_KEY_SIZE];
            Buffer.BlockCopy(opened_msg, SIG_SIZE, lt_cli_pk, 0, PUB_KEY_SIZE);

            var shared_hashed = CryptoHash.Sha256(_shared_ab);
            // Concat network_key, server longterm pk and sha256 hashed shared_ab secret
            var to_verify = Utils.Concat(
                _network_key, _longterm_server_keypair.PublicKey, shared_hashed
            );

            if (!PublicKeyAuth.VerifyDetached(detached_signature, to_verify, lt_cli_pk))
            {
                throw new ArgumentException("Signature does not match");
            }

            detached_signature_A = detached_signature;
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
            var detached_signature = PublicKeyAuth.SignDetached(
                Utils.Concat(
                    _network_key,
                    detached_signature_A,
                    _longterm_client_pk,
                    CryptoHash.Sha256(_shared_ab)
                ),
                _longterm_server_keypair.PrivateKey
            );

            // A nonce consisting of 24 zeros
            var nonce = new byte[NONCE_SIZE];
            nonce.Initialize();

            var key = CryptoHash.Sha256(
                Utils.Concat(_network_key, _shared_ab, _shared_aB, _shared_Ab)
            );

            var msg = SecretBox.Create(detached_signature, nonce, key);

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
            var curve25519Pk = PublicKeyAuth
                .ConvertEd25519PublicKeyToCurve25519PublicKey(
                    this._longterm_client_pk
                );

            this._shared_Ab = ScalarMult.Mult(
                this._ephemeral_server_keypair.PrivateKey,
                curve25519Pk
            );
        }
    }
}
