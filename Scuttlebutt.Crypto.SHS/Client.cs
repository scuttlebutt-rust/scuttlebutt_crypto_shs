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
    ///   Handles the client protocol part of the SHS handshake
    /// </summary>
    public class Client
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

        /// <summary>
        ///   The generated ephemeral key
        /// </summary>
        public byte[] ClientEphemeralPubKey
        {
            get { return _ephemeral_client_keypair.PublicKey; }
        }

        /// <summary>
        ///   The server's sent ephemeral key
        /// </summary>
        public byte[] ServerEphemeralPubKey
        {
            get { return _ephemeral_server_pk; }
        }

        // Constants
        private const int SECTION_LENGTH = 32;
        private const int NONCE_SIZE = 24;

        // Known network key
        private readonly byte[] _network_key;

        // Client keys
        readonly private SHS.KeyPair _ephemeral_client_keypair;
        readonly private Sodium.KeyPair _longterm_client_keypair;

        // Server keys
        private byte[] _ephemeral_server_pk;
        readonly private byte[] _longterm_server_pk;

        // Shared secrets
        private byte[] _shared_ab;
        private byte[] _shared_aB;
        private byte[] _shared_Ab;

        // Detached signature to verify handshake
        private byte[] detached_signature_A;


        /// <summary>
        ///   Constructs the client given
        /// </summary>
        /// <param name="network_key">
        ///   The key that identifies the network
        /// </param>
        /// <param name="server_pk">
        ///   The long term server public key
        /// </param>
        /// <param name="client_keys">
        ///   The long term client key pair
        /// </param>
        public Client(byte[] network_key, byte[] server_pk, Sodium.KeyPair client_keys)
        {
            this._network_key = network_key;

            var ed_keypair =  PublicKeyAuth.GenerateKeyPair();
            _ephemeral_client_keypair = new KeyPair(ed_keypair);

            _longterm_server_pk = server_pk;
            _longterm_client_keypair = client_keys;
        }

        /// <summary>
        ///   Crafts the client's hello message.
        /// </summary>
        /// <remarks>
        ///   Signs the ephemeral public key with the network key and appends
        ///   that key.
        /// </remarks>
        /// <returns>
        ///   The message to be sent
        /// </returns>
        public byte[] Hello()
        {
            var signed_key = SecretKeyAuth.Sign(
                this._ephemeral_client_keypair.PublicKey,
                this._network_key
            );

            var msg = Utils.Concat(
                signed_key, _ephemeral_client_keypair.PublicKey
            );

            return msg;
        }

        /// <summary>
        ///   Validate server Hello and extract ephemeral key
        /// </summary>
        /// <remarks>
        ///   Here the client verifies that the received message length is 64
        ///   bytes, then extracts the server's ephemeral key and also verifies
        ///   that the hmac was signed with the network key.
        ///
        ///   This sets the object's <see cref="_ephemeral_server_pk"/>
        /// </remarks>
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
            var ephemeral_server_key = new byte[SECTION_LENGTH];
            Buffer.BlockCopy(msg, SECTION_LENGTH, ephemeral_server_key, 0, SECTION_LENGTH);
            var hmac = new byte[SECTION_LENGTH];
            Buffer.BlockCopy(msg, 0, hmac, 0, SECTION_LENGTH);

            // Check if the key used to sign the hmac of the ephemeral_client_key is
            // valid
            //
            // Aka, check if we are in the same network
            if (!SecretKeyAuth.Verify(ephemeral_server_key, hmac, _network_key))
            {
                throw new ArgumentException("The hmac does not match");
            }
            else
            {
                this._ephemeral_server_pk = ephemeral_server_key;
            }

            // Now that we have the server's ephemeral public key we can derive
            // the secret
            this.DeriveSecrets();
        }

        /// <summary>
        ///   Crafts the client Authenticate message
        /// </summary>
        /// <remarks>
        ///   Consists of a signature of the network identifier, the server's
        ///   long term public key and a sha 256 of the derived secret ab,
        ///   concatenated with the client's long term public key. All
        ///   encrypted using the network identifier and the derived secrets
        ///   ab and aB.
        ///
        ///   This sets the object's <see cref="detached_signature_A"/>
        /// </remarks>
        /// <returns>
        ///   The client Authenticate message
        /// </returns>
        public byte[] Authenticate()
        {
            var hash_ab = CryptoHash.Sha256(this._shared_ab);

            // Concatenate the network identifier, the server's public key and
            // the hash of the derived secret.
            var to_sign = Utils.Concat(
                _network_key, _longterm_server_pk, hash_ab
            );

            // Sign the first portion of the message and save it in the object
            // state for later use in the server accept verification.
            detached_signature_A = PublicKeyAuth.SignDetached(
                to_sign, _longterm_client_keypair.PrivateKey
            );

            // Create the plaintext message
            var plaintext = Utils.Concat(
                detached_signature_A, _longterm_client_keypair.PublicKey
            );

            // Create the key from the network key and the shared secrets
            var box_key = Utils.Concat(
                _network_key, _shared_ab, _shared_aB
            );

            // A nonce consisting of 24 zeros
            var nonce = new byte[NONCE_SIZE];
            nonce.Initialize();

            var msg = SecretBox.Create(plaintext, nonce, CryptoHash.Sha256(box_key));
            return msg;
        }

        /// <summary>
        ///   Validates server acceptance message
        /// </summary>
        /// <remarks>
        ///   Here the client verifies that the received message length is 80
        ///   bytes, then opens the encrypted box and verifies that the sent
        ///   message is server's signature to the derived shared secrets. With
        ///   this the handshake concludes.
        /// </remarks>
        /// <exception cref="ArgumentException">
        ///   Thrown if the server's Accept <paramref name="msg"/> is not the
        ///   correct size or the signature is not valid.
        /// </exception>
        /// <param name="msg">
        ///   The received message, encrypted server's signature.
        /// </param>
        public void VerifyAccept(byte[] msg)
        {
            if ( msg.Length != 80 )
            {
                throw new ArgumentException("Incorrect message size");
            }

            var nonce = new byte[NONCE_SIZE];
            nonce.Initialize();

            // Concatenate the network key and derived secrets to obtain
            // the message key
            var key = CryptoHash.Sha256(
                Utils.Concat(_network_key, _shared_ab, _shared_aB, _shared_Ab)
            );

            var opened_msg = SecretBox.Open(msg, nonce, key);

            // Compute the message that it is supposed to be signed with the
            // server's long term key
            var hashed = CryptoHash.Sha256(_shared_ab);
            var msg_to_verify = Utils.Concat(
                _network_key, detached_signature_A,
                _longterm_client_keypair.PublicKey, hashed
            );

            if ( !PublicKeyAuth.VerifyDetached(opened_msg, msg_to_verify, _longterm_server_pk) )
            {
                throw new ArgumentException("Invalid signature");
            }
        }

        private void DeriveSecrets()
        {
            var curve25519Sk = PublicKeyAuth
                .ConvertEd25519SecretKeyToCurve25519SecretKey(
                    this._longterm_client_keypair.PrivateKey
                );

            var curve25519Pk = PublicKeyAuth
                .ConvertEd25519PublicKeyToCurve25519PublicKey(
                    _longterm_server_pk
                );

            this._shared_ab = ScalarMult.Mult(
                this._ephemeral_client_keypair.PrivateKey,
                this._ephemeral_server_pk
            );

            this._shared_aB = ScalarMult.Mult(
                this._ephemeral_client_keypair.PrivateKey,
                curve25519Pk
            );

            this._shared_Ab = ScalarMult.Mult(
                curve25519Sk,
                _ephemeral_server_pk
            );
        }
    }
}
