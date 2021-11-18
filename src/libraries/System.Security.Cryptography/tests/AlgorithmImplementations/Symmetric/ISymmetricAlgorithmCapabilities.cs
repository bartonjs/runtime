// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

namespace System.Security.Cryptography.Tests.AlgorithmImplementations.Symmetric
{
    public interface ISymmetricAlgorithmCapabilities<TSelf>
        where TSelf : ISymmetricAlgorithmCapabilities<TSelf>
    {
        static abstract bool CanReadKeyProperty { get; }
        static abstract bool HasOneShots { get; }
    }
}
