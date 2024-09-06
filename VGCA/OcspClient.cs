using iTextSharp.text.pdf.security;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.Utilities;
using System.Collections;
using System.Net;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.X509;

namespace VGCA
{
    public class OcspClient
    {
        private readonly long MaxClockSkew = 360000000;
        public static readonly int BufferSize = 32768;
        private int port;
        private WebProxy proxy;

        public int Port
        {
            get => this.port;
            set => this.port = value;
        }

        public WebProxy Proxy
        {
            get => this.proxy;
            set => this.proxy = value;
        }

        private byte[] PostData(string url, byte[] data, string contentType, string accept)
        {
            if (this.port != 0)
            {
                Uri uri = new Uri(url);
                url = url.Replace(uri.Host, string.Format("{0}:{1}", (object)uri.Host, (object)this.port));
            }
            Stream stream1 = (Stream)null;
            HttpWebResponse httpWebResponse = (HttpWebResponse)null;
            Stream stream2 = (Stream)null;
            try
            {
                HttpWebRequest httpWebRequest = (HttpWebRequest)WebRequest.Create(url);
                if (this.proxy != null)
                    httpWebRequest.Proxy = (IWebProxy)this.proxy;
                httpWebRequest.ProtocolVersion = HttpVersion.Version10;
                httpWebRequest.Method = "POST";
                httpWebRequest.ContentType = contentType;
                httpWebRequest.ContentLength = (long)data.Length;
                httpWebRequest.Accept = accept;
                stream1 = httpWebRequest.GetRequestStream();
                stream1.Write(data, 0, data.Length);
                stream1.Close();
                httpWebResponse = (HttpWebResponse)httpWebRequest.GetResponse();
                stream2 = httpWebResponse.GetResponseStream();
                byte[] byteArray = this.ToByteArray(stream2);
                stream2.Close();
                return byteArray;
            }
            catch (Exception ex)
            {
                throw new Exception("Không thể gửi yêu cầu kiểm tra chứng thư số.", ex);
            }
            finally
            {
                stream1?.Close();
                stream2?.Close();
                httpWebResponse?.Close();
            }
        }

        private byte[] ToByteArray(Stream stream)
        {
            using (MemoryStream memoryStream = new MemoryStream())
            {
                byte[] buffer = new byte[OcspClient.BufferSize];
                int count;
                while ((count = stream.Read(buffer, 0, buffer.Length)) > 0)
                    memoryStream.Write(buffer, 0, count);
                return memoryStream.ToArray();
            }
        }

        public CertificateStatus Query(X509Certificate eeCert, X509Certificate issuerCert)
        {
            string ocspurl = CertificateUtil.GetOCSPURL(eeCert);
            if (string.IsNullOrEmpty(ocspurl))
                throw new Exception("Không tìm thấy thông tin OCSP trên chứng thư số.");
            OcspReq ocspRequest = this.GenerateOcspRequest(issuerCert, eeCert.SerialNumber);
            byte[] binaryResp = this.PostData(ocspurl, ocspRequest.GetEncoded(), "application/ocsp-request", "application/ocsp-response");
            return this.ProcessOcspResponse(eeCert, issuerCert, binaryResp);
        }

        private CertificateStatus ProcessOcspResponse(
          X509Certificate eeCert,
          X509Certificate issuerCert,
          byte[] binaryResp)
        {
            OcspResp ocspResp = new OcspResp(binaryResp);
            CertificateStatus certificateStatus = CertificateStatus.Unknown;
            BasicOcspResp or = ocspResp.Status == 0 ? (BasicOcspResp)ocspResp.GetResponseObject() : throw new Exception("Phản hồi OCSP không hợp lệ '" + ocspResp.Status.ToString() + "'.");
            this.ValidateResponse(or, issuerCert);
            if (or.Responses.Length == 1)
            {
                SingleResp response = or.Responses[0];
                this.ValidateCertificateId(issuerCert, eeCert, response.GetCertID());
                object certStatus = response.GetCertStatus();
                if (certStatus == Org.BouncyCastle.Ocsp.CertificateStatus.Good)
                {
                    certificateStatus = CertificateStatus.Good;
                }
                else
                {
                    switch (certStatus)
                    {
                        case RevokedStatus _:
                            certificateStatus = CertificateStatus.Revoked;
                            break;
                        case UnknownStatus _:
                            certificateStatus = CertificateStatus.Unknown;
                            break;
                    }
                }
            }
            return certificateStatus;
        }

        private void ValidateResponse(BasicOcspResp or, X509Certificate issuerCert)
        {
            this.ValidateResponseSignature(or, issuerCert.GetPublicKey());
            this.ValidateSignerAuthorization(issuerCert, or.GetCerts()[0]);
        }

        private void ValidateSignerAuthorization(X509Certificate issuerCert, X509Certificate signerCert)
        {
            if (!issuerCert.SubjectDN.Equivalent(signerCert.IssuerDN))
                throw new Exception("OCSP không xác thực");
        }

        private void ValidateResponseSignature(
          BasicOcspResp or,
          AsymmetricKeyParameter asymmetricKeyParameter)
        {
            try
            {
                or.GetCerts()[0].Verify(asymmetricKeyParameter);
            }
            catch
            {
                throw new Exception("OCSP không hợp lệ");
            }
            if (!or.Verify(or.GetCerts()[0].GetPublicKey()))
                throw new Exception("OCSP không hợp lệ");
        }

        private void ValidateNextUpdate(SingleResp resp)
        {
            if (resp.NextUpdate == null)
                return;
            DateTime dateTime = resp.NextUpdate.Value;
            if (resp.NextUpdate.Value.Ticks <= DateTime.Now.Ticks)
                throw new Exception("Invalid next update.");
        }

        private void ValidateThisUpdate(SingleResp resp)
        {
            DateTime dateTime = resp.ThisUpdate;
            long ticks1 = dateTime.Ticks;
            dateTime = DateTime.Now;
            long ticks2 = dateTime.Ticks;
            if (System.Math.Abs(ticks1 - ticks2) > this.MaxClockSkew)
                throw new Exception("Max clock skew reached.");
        }

        private void ValidateCertificateId(
          X509Certificate issuerCert,
          X509Certificate eeCert,
          CertificateID certificateId)
        {
            CertificateID certificateId1 = new CertificateID("1.3.14.3.2.26", issuerCert, eeCert.SerialNumber);
            if (!certificateId1.SerialNumber.Equals((object)certificateId.SerialNumber))
                throw new Exception("Không đúng chứng thư số cần kiểm tra trên kết qua trả về");
            if (!Arrays.AreEqual(certificateId1.GetIssuerNameHash(), certificateId.GetIssuerNameHash()))
                throw new Exception("Không đúng chứng thư số cơ quan cấp phát trên kết quả trả về");
        }

        private OcspReq GenerateOcspRequest(X509Certificate issuerCert, BigInteger serialNumber)
        {
            return this.GenerateOcspRequest(new CertificateID("1.3.14.3.2.26", issuerCert, serialNumber));
        }

        private OcspReq GenerateOcspRequest(CertificateID id)
        {
            OcspReqGenerator ocspReqGenerator = new OcspReqGenerator();
            ocspReqGenerator.AddRequest(id);
            BigInteger.ValueOf(new DateTime().Ticks);
            ArrayList ordering = new ArrayList();
            Hashtable extensions = new Hashtable();
            ordering.Add((object)OcspObjectIdentifiers.PkixOcsp);
            Asn1OctetString asn1OctetString = (Asn1OctetString)new DerOctetString((Asn1Encodable)new DerOctetString(new byte[10]
            {
        (byte) 1,
        (byte) 3,
        (byte) 6,
        (byte) 1,
        (byte) 5,
        (byte) 5,
        (byte) 7,
        (byte) 48,
        (byte) 1,
        (byte) 1
            }));
            extensions.Add((object)OcspObjectIdentifiers.PkixOcsp, (object)new X509Extension(false, asn1OctetString));
            ocspReqGenerator.SetRequestExtensions(new X509Extensions(ordering, extensions));
            return ocspReqGenerator.Generate();
        }
    }
}
