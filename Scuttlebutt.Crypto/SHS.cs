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
            get
            {
                return _shared_ab;
            }
        }
        /// <summary>
        ///   The secret derived from the client ephemeral key and the server's
        ///   long term key (aB).
        /// </summary>
        public byte[] ServerDerivedSecret
        {
            get
            {
                return _shared_aB;
            }
        }
        /// <summary>
        ///   The secret derived from the client long term key and the server's
        ///   ephemeral key (Ab).
        /// </summary>
        public byte[] ClientDerivedSecret
        {
            get
            {
                return _shared_Ab;
            }
        }

        // Constants
        private const int SECTION_LENGTH = 32;
        private const int NONCE_SIZE = 24;

        // Known network key
        private readonly byte[] _network_key;

        // Client keys
        private KeyPair _ephemeral_client_keypair;
        private KeyPair _longterm_client_keypair;

        // Server keys
        private byte[] _ephemeral_server_pk;
        private byte[] _longterm_server_pk;

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
        public Client(byte[] network_key, byte[] server_pk, KeyPair client_keys)
        {
            this._network_key = network_key;
            _ephemeral_client_keypair = PublicKeyAuth.GenerateKeyPair();
            _longterm_server_pk = server_pk;
            _longterm_client_keypair = client_keys;
        }

        /// <summary>
        ///   Crafts the client's hello message.
        /// </summary>
        /// <remark>
        ///   Signs the ephemeral public key with the network key and appends
        ///   that key.
        /// </remark>
        /// <returns>
        ///   The message to be sent
        /// </returns>
        public byte[] Hello()
        {
            var signed_key = SecretKeyAuth.Sign(
                _ephemeral_client_keypair.PrivateKey,
                _network_key
            );

            var msg = new byte[SECTION_LENGTH * 2];

            return msg;
        }

        /// <summary>
        ///   Validate server Hello and extract ephemeral key
        /// </summary>
        /// <remark>
        ///   Here the client verifies that the received message length is 64
        ///   bytes, then extracts the server's ephemeral key and also verifies
        ///   that the hmac was signed with the network key.
        ///
        ///   This sets the object's <see cref="_ephemeral_server_pk"/>
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
            var ephemeral_server_key = new byte[SECTION_LENGTH];
            Buffer.BlockCopy(msg, 0, ephemeral_server_key, 0, SECTION_LENGTH);
            var hmac = new byte[SECTION_LENGTH];
            Buffer.BlockCopy(msg, SECTION_LENGTH, hmac, 0, SECTION_LENGTH);

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
        /// <remark>
        ///   Consists of a signature of the network identifier, the server's
        ///   long term public key and a sha 256 of the derived secret ab,
        ///   concatenated with the client's long term public key. All
        ///   encrypted using the network identifier and the derived secrets
        ///   ab and aB.
        ///
        ///   This sets the object's <see cref="detached_signature_A"/>
        /// </remark>
        /// <returns>
        ///   The client Authenticate message
        /// </returns>
        public byte[] Authenticate()
        {
            var hash_ab = CryptoHash.Hash(this._shared_ab);

            // Concatenate the network identifier, the server's public key and
            // the hash of the derived secret.
            var to_sign = new byte[_network_key.Length + _longterm_server_pk.Length + hash_ab.Length];
            _network_key.CopyTo(to_sign, 0);
            _longterm_server_pk.CopyTo(to_sign, _network_key.Length);
            hash_ab.CopyTo(to_sign, _longterm_server_pk.Length);

            // Sign the first portion of the message and save it in the object
            // state for later use in the server accept verification.
            var signature = PublicKeyAuth.SignDetached(to_sign, _longterm_client_keypair.PrivateKey);
            detached_signature_A = signature;

            // Create the plaintext message
            var plaintext = new byte[_longterm_client_keypair.PublicKey.Length + signature.Length];
            signature.CopyTo(plaintext, 0);
            _longterm_client_keypair.PublicKey.CopyTo(plaintext, signature.Length);

            // Create the key from the network key and the shared secrets
            var box_key = new byte[_network_key.Length + _shared_ab.Length + _shared_aB.Length];
            _network_key.CopyTo(box_key, 0);
            _shared_ab.CopyTo(box_key, _network_key.Length);
            _shared_aB.CopyTo(box_key, _shared_ab.Length);

            // A nonce consisting of 24 zeros
            var nonce = new byte[NONCE_SIZE];
            nonce.Initialize();

            var msg = SecretBox.Create(plaintext, nonce, box_key);
            return msg;
        }

        /// <summary>
        ///   Validates server acceptance message
        /// </summary>
        /// <remark>
        ///   Here the client verifies that the received message length is 80
        ///   bytes, then opens the encrypted box and verifies that the sent
        ///   message is server's signature to the derived shared secrets. With
        ///   this the handshake concludes.
        /// </remark>
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
            var to_hash = new byte[0];
            var msg_key = CryptoHash.Sha256(
                to_hash
                    .Concat(_network_key)
                    .Concat(_shared_ab)
                    .Concat(_shared_aB)
                    .Concat(_shared_Ab)
            );

            var opened_msg = SecretBox.Open(msg, nonce, msg_key);

            // Compute the message that it is supposed to be signed with the
            // server's long term key
            var hashed = CryptoHash.Sha256(_shared_ab);
            var msg_to_verify = new byte[0];
            msg_to_verify
                .Concat(_network_key)
                .Concat(detached_signature_A)
                .Concat(_longterm_client_keypair.PublicKey)
                .Concat(hashed);

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
                curve25519Sk,
                _ephemeral_server_pk
            );

            this._shared_Ab = ScalarMult.Mult(
                curve25519Sk,
                _ephemeral_server_pk
            );
        }
    }

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
            get
            {
                return _shared_ab;
            }
        }
        /// <summary>
        ///   The secret derived from the client ephemeral key and the server's
        ///   long term key (aB).
        /// </summary>
        public byte[] ServerDerivedSecret
        {
            get
            {
                return _shared_aB;
            }
        }
        /// <summary>
        ///   The secret derived from the client long term key and the server's
        ///   ephemeral key (Ab).
        /// </summary>
        public byte[] ClientDerivedSecret
        {
            get
            {
                return _shared_Ab;
            }
        }

        // Constants
        private const int SECTION_LENGTH = 32;
        private const int SIG_SIZE = 64;
        private const int PUB_KEY_SIZE = 32;
        private const int NONCE_SIZE = 24;

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
            Buffer.BlockCopy(msg, 0, ephemeral_client_key, 0, SECTION_LENGTH);
            var hmac = new byte[SECTION_LENGTH];
            Buffer.BlockCopy(msg, SECTION_LENGTH, hmac, 0, SECTION_LENGTH);

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
            var nonce = new byte[NONCE_SIZE];
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
            var curve25519Pk = PublicKeyAuth
                .ConvertEd25519PublicKeyToCurve25519PublicKey(
                    this._longterm_client_pk
                );

            this._shared_Ab = ScalarMult.Mult(
                this._ephemeral_server_keypair.PublicKey,
                curve25519Pk
            );
        }
    }
}
