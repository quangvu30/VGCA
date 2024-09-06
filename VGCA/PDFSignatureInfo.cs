using System;
using System.Collections.Generic;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace VGCA
{
    public struct PDFSignatureInfo
    {
        public string SignatureName;
        public bool SignatureCoversWholeDocument;
        public DateTime SigningTime;
        public DateTime TimeStampDate;
        public byte[] SigningCertificate;
        public byte[] TimeStampCertificate;
        public Rectangle Position;
        public int PageIndex;
        public Dictionary<SignatureValidity, string> ValidityErrors;
        public bool IsTsp;
    }
}
