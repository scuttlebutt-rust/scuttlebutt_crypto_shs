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

using Sodium;

namespace Scuttlebutt.Crypto.SHS
{
    internal class KeyPair
    {
        public byte[] PublicKey;
        public byte[] PrivateKey;

        public KeyPair(Sodium.KeyPair a)
        {
            this.PublicKey = PublicKeyAuth
                .ConvertEd25519PublicKeyToCurve25519PublicKey(a.PublicKey);
            this.PrivateKey = PublicKeyAuth
                .ConvertEd25519SecretKeyToCurve25519SecretKey(a.PrivateKey);
        }
    }
}
