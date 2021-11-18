// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

namespace System.Security.Cryptography.Tests.AlgorithmImplementations.Symmetric
{
    public enum SymmetricTestModes
    {
        TransformFinalBlock,
        TransformFinalBlockParameterized,
        CryptoStream,
        OneShotArray,
        OneShotSpan,
    }
}
