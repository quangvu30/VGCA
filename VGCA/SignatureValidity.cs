using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace VGCA
{
    public enum SignatureValidity
    {
        None = 0,
        NotSigned = 1,
        DocumentModified = 2,
        NotTimestamped = 4,
        InvalidTimestampImprint = 8,
        InvalidTSACertificate = 16, // 0x00000010
        InvalidSigningCertificate = 32, // 0x00000020
        ErrorCheckingSigningCertificate = 64, // 0x00000040
        ErrorCheckingTSACertificate = 128, // 0x00000080
        NonCheckingRevokedSigningCert = 256, // 0x00000100
        NonCheckingRevokedTSACert = 512, // 0x00000200
        NonCoversWholeDocument = 1024, // 0x00000400
        ErrorCheckingSignature = 2048, // 0x00000800
        FatalError = 4096, // 0x00001000
    }
}
