// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

namespace System.IO.Hashing.Tests
{
    public class CustomCksumDriver : Crc32DriverBase
    {
        internal override Crc32ParameterSet ParameterSet => field ??= Crc32ParameterSet.Create(
            polynomial: 0x04C11DB7,
            initialValue: 0x00000000,
            finalXorValue: 0xFFFFFFFF,
            reflectInput: false,
            reflectOutput: false);

        internal override string EmptyOutput => "FFFFFFFF";
        internal override string Residue => "38FB2284";

        internal override string? GetExpectedOutput(string testCaseName) =>
            testCaseName switch
            {
                "One" => "FB3EE248",
                "Zero" => "FFFFFFFF",
                "Self-test 123456789" => "765E7680",
                "The quick brown fox jumps over the lazy dog" => "36B78081",
                "Lorem ipsum 128" => "CD8EF435",
                "Lorem ipsum 144" => "04BD8AF7",
                "Lorem ipsum 1001" => "CD98BE63",
                _ => throw new ArgumentOutOfRangeException(nameof(testCaseName), testCaseName, "Unmapped Value"),
            };
    }

    public class Crc32Tests_ParameterSet_Custom_Cksum : Crc32Tests_Parameterized<CustomCksumDriver>
    {
    }
}
