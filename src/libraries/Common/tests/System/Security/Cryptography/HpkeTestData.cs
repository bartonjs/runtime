// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Collections.Generic;

namespace System.Security.Cryptography.Tests
{
    public enum HpkeMode
    {
        Base = 0,
        PSK = 1,
        Auth = 2,
        AuthPSK = 3,
    }

    public record HpkeTestVector(
        HpkeMode Mode,
        HpkeSuite Suite,
        string RecipientPrivateKey,
        string Enc,
        string Info,
        string Aad0,
        string Plaintext0,
        string Ciphertext0,
        string? SenderPublicKey = null,
        string? Psk = null,
        string? PskId = null,
        string? Aad1 = null,
        string? Plaintext1 = null,
        string? Ciphertext1 = null,
        string? Aad2 = null,
        string? Ciphertext2 = null);

    public static class HpkeTestData
    {
        public static IEnumerable<object[]> BaseVectors
        {
            get
            {
                foreach (HpkeTestVector vector in AllVectors)
                {
                    if (vector.Mode == HpkeMode.Base)
                    {
                        yield return [vector];
                    }
                }
            }
        }

        public static IEnumerable<object[]> PskVectors
        {
            get
            {
                foreach (HpkeTestVector vector in AllVectors)
                {
                    if (vector.Mode == HpkeMode.PSK)
                    {
                        yield return [vector];
                    }
                }
            }
        }

        public static IEnumerable<object[]> AuthVectors
        {
            get
            {
                foreach (HpkeTestVector vector in AllVectors)
                {
                    if (vector.Mode == HpkeMode.Auth)
                    {
                        yield return [vector];
                    }
                }
            }
        }

        public static IEnumerable<object[]> AuthPskVectors
        {
            get
            {
                foreach (HpkeTestVector vector in AllVectors)
                {
                    if (vector.Mode == HpkeMode.AuthPSK)
                    {
                        yield return [vector];
                    }
                }
            }
        }

        // RFC 9180 Appendix A test vectors for DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-128-GCM
        public static IEnumerable<HpkeTestVector> AllVectors
        {
            get
            {
                // A.3.1 - Base Mode (mode=0x00)
                yield return new HpkeTestVector(
                    Mode: HpkeMode.Base,
                    Suite: HpkeSuite.DHKEM_P256_HKDF_SHA256_AES_128_GCM,
                    RecipientPrivateKey: "f3ce7fdae57e1a310d87f1ebbde6f328be0a99cdbcadf4d6589cf29de4b8ffd2",
                    Enc: "04a92719c6195d5085104f469a8b9814d5838ff72b60501e2c4466e5e67b32" +
                         "5ac98536d7b61a1af4b78e5b7f951c0900be863c403ce65c9bfcb9382657222d18c4",
                    Info: "4f6465206f6e2061204772656369616e2055726e",
                    Aad0: "436f756e742d30",
                    Plaintext0: "4265617574792069732074727574682c20747275746820626561757479",
                    Ciphertext0: "5ad590bb8baa577f8619db35a36311226a896e7342a6d836d8b7bcd2f20b6c" +
                                 "7f9076ac232e3ab2523f39513434");

                // A.3.2 - PSK Mode (mode=0x01)
                yield return new HpkeTestVector(
                    Mode: HpkeMode.PSK,
                    Suite: HpkeSuite.DHKEM_P256_HKDF_SHA256_AES_128_GCM,
                    RecipientPrivateKey: "438d8bcef33b89e0e9ae5eb0957c353c25a94584b0dd59c991372a75b43cb661",
                    Enc: "04305d35563527bce037773d79a13deabed0e8e7cde61eecee403496959e89" +
                         "e4d0ca701726696d1485137ccb5341b3c1c7aaee90a4a02449725e744b1193b53b5f",
                    Info: "4f6465206f6e2061204772656369616e2055726e",
                    Psk: "0247fd33b913760fa1fa51e1892d9f307fbe65eb171e8132c2af18555a738b82",
                    PskId: "456e6e796e20447572696e206172616e204d6f726961",
                    Aad0: "436f756e742d30",
                    Plaintext0: "4265617574792069732074727574682c20747275746820626561757479",
                    Ciphertext0: "90c4deb5b75318530194e4bb62f890b019b1397bbf9d0d6eb918890e1fb2be" +
                                 "1ac2603193b60a49c2126b75d0eb",
                    Aad1: "436f756e742d31",
                    Plaintext1: "4265617574792069732074727574682c20747275746820626561757479",
                    Ciphertext1: "9e223384a3620f4a75b5a52f546b7262d8826dea18db5a365feb8b997180b2" +
                                 "2d72dc1287f7089a1073a7102c27",
                    Aad2: "436f756e742d32",
                    Ciphertext2: "adf9f6000773035023be7d415e13f84c1cb32a24339a32eb81df02be9ddc6a" +
                                 "bc880dd81cceb7c1d0c7781465b2");

                // A.3.3 - Auth Mode (mode=0x02)
                yield return new HpkeTestVector(
                    Mode: HpkeMode.Auth,
                    Suite: HpkeSuite.DHKEM_P256_HKDF_SHA256_AES_128_GCM,
                    RecipientPrivateKey: "d929ab4be2e59f6954d6bedd93e638f02d4046cef21115b00cdda2acb2a4440e",
                    SenderPublicKey: "04a817a0902bf28e036d66add5d544cc3a0457eab150f104285df1e293b5c10eef" +
                                    "8651213e43d9cd9086c80b309df22cf37609f58c1127f7607e85f210b2804f73",
                    Enc: "042224f3ea800f7ec55c03f29fc9865f6ee27004f818fcbdc6dc68932c1e52e15b" +
                         "79e264a98f2c535ef06745f3d308624414153b22c7332bc1e691cb4af4d53454",
                    Info: "4f6465206f6e2061204772656369616e2055726e",
                    Aad0: "436f756e742d30",
                    Plaintext0: "4265617574792069732074727574682c20747275746820626561757479",
                    Ciphertext0: "82ffc8c44760db691a07c5627e5fc2c08e7a86979ee79b494a17cc3405446a" +
                                 "c2bdb8f265db4a099ed3289ffe19");

                // A.3.4 - AuthPSK Mode (mode=0x03)
                yield return new HpkeTestVector(
                    Mode: HpkeMode.AuthPSK,
                    Suite: HpkeSuite.DHKEM_P256_HKDF_SHA256_AES_128_GCM,
                    RecipientPrivateKey: "bdf4e2e587afdf0930644a0c45053889ebcadeca662d7c755a353d5b4e2a8394",
                    SenderPublicKey: "049f158c750e55d8d5ad13ede66cf6e79801634b7acadcad72044eac2ae1d04800" +
                                    "69133d6488bf73863fa988c4ba8bde1c2e948b761274802b4d8012af4f13af9e",
                    Enc: "046a1de3fc26a3d43f4e4ba97dbe24f7e99181136129c48fbe872d4743e2b13135" +
                         "7ed4f29a7b317dc22509c7b00991ae990bf65f8b236700c82ab7c11a84511401",
                    Info: "4f6465206f6e2061204772656369616e2055726e",
                    Psk: "0247fd33b913760fa1fa51e1892d9f307fbe65eb171e8132c2af18555a738b82",
                    PskId: "456e6e796e20447572696e206172616e204d6f726961",
                    Aad0: "436f756e742d30",
                    Plaintext0: "4265617574792069732074727574682c20747275746820626561757479",
                    Ciphertext0: "b9f36d58d9eb101629a3e5a7b63d2ee4af42b3644209ab37e0a272d4436540" +
                                 "7db8e655c72e4fa46f4ff81b9246");
            }
        }
    }
}
