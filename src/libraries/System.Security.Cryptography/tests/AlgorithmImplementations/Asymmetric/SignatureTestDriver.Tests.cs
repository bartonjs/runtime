// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using Test.Cryptography;
using Xunit;
using Xunit.Sdk;

namespace System.Security.Cryptography.Tests.AlgorithmImplementations.Asymmetric
{
    public abstract partial class SignatureTestDriver<TAlgorithm, TCapabilities>
        where TAlgorithm : AsymmetricAlgorithm
        where TCapabilities : ISignatureAlgorithmCapabilities<TCapabilities>
    {
        [Theory, MemberData(nameof(VerifyModes))]
        public void VerifyKnownSignatures(VerifyMode verifyMode)
        {
            var state = (Mode: verifyMode, This: this);

            ForEachCaseAllKeys(
                ref state,
                null,
                static (
                    ref (VerifyMode Mode, SignatureTestDriver<TAlgorithm, TCapabilities> This) state,
                    SignatureKnownValueTestCase<TAlgorithm> testCase,
                    TAlgorithm key) =>
                {
                    bool verified = state.This.Verify(
                        key,
                        testCase.Data,
                        testCase.LazyGetHash(state.Mode)!,
                        testCase.Signature,
                        testCase.HashAlgorithm,
                        state.Mode);

                    Assert.True(verified, "Known signature verified correctly");
                }
            );
        }

        [Theory, MemberData(nameof(VerifyModes))]
        public void VerifyTamperedDataSignatures(VerifyMode verifyMode)
        {
            var state = (Mode: verifyMode, Hash: (byte[])null, Data: (ArraySegment<byte>)null, This: this);

            ForEachCaseAllKeys(
                ref state,
                static (
                    ref (VerifyMode Mode, byte[] Hash, ArraySegment<byte> Data, SignatureTestDriver<TAlgorithm, TCapabilities> This) state,
                    SignatureKnownValueTestCase<TAlgorithm> testCase) =>
                {
                    if (testCase.Data.Count != 0)
                    {
                        byte[] arr = (byte[])testCase.Data.Array!.Clone();
                        arr[testCase.Data.Offset - 1 + testCase.Data.Count] ^= 1;
                        state.Data = new ArraySegment<byte>(arr, testCase.Data.Offset, testCase.Data.Count);
                    }
                    else
                    {
                        state.Data = new byte[1];
                    }

                    if (state.Mode == VerifyMode.VerifyHashArray ||
                        state.Mode == VerifyMode.VerifyHashSpan)
                    {
                        state.Hash = CryptoUtils.HashData(testCase.HashAlgorithm, state.Data);
                    }
                },
                static (
                    ref (VerifyMode Mode, byte[] Hash, ArraySegment<byte> Data, SignatureTestDriver<TAlgorithm, TCapabilities> This) state,
                    SignatureKnownValueTestCase<TAlgorithm> testCase,
                    TAlgorithm key) =>
                {
                    bool verified = state.This.Verify(
                        key,
                        state.Data,
                        state.Hash,
                        testCase.Signature,
                        testCase.HashAlgorithm,
                        state.Mode);

                    Assert.False(verified, "Known tampered signature verified correctly");
                }
            );
        }

        [Theory, MemberData(nameof(VerifyModes))]
        public void VerifyTamperedSignatures(VerifyMode verifyMode)
        {
            var state = (Mode: verifyMode, Signature: (byte[])null, This: this);

            ForEachCaseAllKeys(
                ref state,
                static (
                    ref (VerifyMode Mode, byte[] Signature, SignatureTestDriver<TAlgorithm, TCapabilities> This) state,
                    SignatureKnownValueTestCase<TAlgorithm> testCase) =>
                {
                    state.Signature = (byte[])testCase.Signature.Clone();
                    state.Signature[^5] |= 1;
                },
                static (
                    ref (VerifyMode Mode, byte[] Signature, SignatureTestDriver<TAlgorithm, TCapabilities> This) state,
                    SignatureKnownValueTestCase<TAlgorithm> testCase,
                    TAlgorithm key) =>
                {
                    bool verified = state.This.Verify(
                        key,
                        testCase.Data,
                        testCase.LazyGetHash(state.Mode)!,
                        state.Signature,
                        testCase.HashAlgorithm,
                        state.Mode);

                    Assert.False(verified, "Known tampered signature verified correctly");
                }
            );
        }

        private delegate void NewTestCaseHandler<TState>(
            ref TState state,
            SignatureKnownValueTestCase<TAlgorithm> testCase);

        private delegate void TestCaseAndKeyHandler<TState>(
            ref TState state,
            SignatureKnownValueTestCase<TAlgorithm> testCase,
            TAlgorithm key);

        private void ForEachCaseAllKeys<TState>(
            ref TState state,
            NewTestCaseHandler<TState>? newCaseHandler,
            TestCaseAndKeyHandler<TState> keyHandler)
        {
            ForEachCaseKey(ref state, newCaseHandler, keyHandler, keyHandler);
        }

        private void ForEachCaseKey<TState>(
            ref TState state,
            NewTestCaseHandler<TState>? newCaseHandler,
            TestCaseAndKeyHandler<TState>? publicKeyHandler,
            TestCaseAndKeyHandler<TState>? privateKeyHandler)
        {
            foreach (SignatureKnownValueTestCase<TAlgorithm> ktc in EnumerateKnownValues())
            {
                newCaseHandler?.Invoke(ref state, ktc);
                TAlgorithm key = null!;

                if (publicKeyHandler != null && ktc.Key.HasPublicKey)
                {
                    foreach (var (loadMode, _) in ktc.Key.LoadPublicKeys(() => key ??= Create()))
                    {
                        try
                        {
                            publicKeyHandler(ref state, ktc, key);
                        }
                        catch (XunitException xe)
                        {
                            throw new XunitException(
                                $"Test case '{ktc}' with a public key loaded by '{loadMode}' - {xe.Message}");
                        }
                        catch (Exception e)
                        {
                            throw new XunitException(
                                $"Unhandled exception from test case '{ktc}' with a public key loaded by '{loadMode}': {e}");
                        }
                    }
                }

                if (privateKeyHandler != null && ktc.Key.HasPrivateKey)
                {
                    foreach (var (loadMode, _) in ktc.Key.LoadPrivateKeys(() => key ??= Create()))
                    {
                        try
                        {
                            privateKeyHandler(ref state, ktc, key);
                        }
                        catch (XunitException xe)
                        {
                            throw new XunitException(
                                $"Test case '{ktc}' with a private key loaded by '{loadMode}' - {xe.Message}");
                        }
                        catch (Exception e)
                        {
                            throw new XunitException(
                                $"Unhandled exception from test case '{ktc}' with a private key loaded by '{loadMode}': {e}");
                        }
                    }
                }

                key?.Dispose();
            }
        }
    }
}
