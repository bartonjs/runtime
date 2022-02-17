// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Diagnostics.Tracing;

namespace System.Security.Cryptography.X509Certificates
{
    [EventSource(Name = "System.Security.Cryptography.X509Certificates.X509Chain.OpenSsl")]
    internal sealed class OpenSslX509ChainEventSource : EventSource
    {
        internal static readonly OpenSslX509ChainEventSource Log = new OpenSslX509ChainEventSource();

        private const int EventId_ChainStart = 1;
        private const int EventId_ChainStop = 2;

        [Event(
            EventId_ChainStart,
            Message = "Starting X.509 chain build.",
            Opcode = EventOpcode.Start,
            Level = EventLevel.Informational)]
        public void ChainStart()
        {
            if (IsEnabled())
            {
                WriteEvent(EventId_ChainStart);
            }
        }

        [Event(
            EventId_ChainStop,
            Opcode = EventOpcode.Stop,
            Level = EventLevel.Informational)]
        public void ChainStop()
        {
            if (IsEnabled())
            {
                WriteEvent(EventId_ChainStop);
            }
        }
    }
}
