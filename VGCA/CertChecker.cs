using iTextSharp.text.pdf.security;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.X509;
using System.Net;
using System.Security.Cryptography.X509Certificates;

namespace VGCA
{
    internal class CertChecker
    {
        public const int CK_OK = 0;
        public const int CERT_EXPIRED = 1;
        public const int CERT_NOT_YET_VALID = 2;
        public const int INVALID_CERT_CHAIN = 3;
        public const int UNTRUSTED_ROOT = 4;
        public const int INVALID_CRL_DIST_POINTS = 5;
        public const int COULDNOT_DOWNLOAD_CRL = 6;
        public const int ONLINE_CHECKING_CERT_DISABLED = 7;
        public const int CERT_IS_REVOKED = 8;
        public const int CA_CERT_IS_REVOKED = 9;
        public const int INVALID_CRL = 10;
        public const int OCSP_RESP_UNKNOWN = 11;
        public const int COULDNOT_DOWNLOAD_CTL = 12;
        private X509Certificate2 _cert;
        private Org.BouncyCastle.X509.X509Certificate[] chain;
        private DateTime _checkingDatetime;
        private bool onlineCheckingAllowed = true;
        private bool checkingViaOcsp;
        private WebProxy proxy;
        private string[] additionalCRLs;
        private static List<X509Certificate2> extraStore;

        public Org.BouncyCastle.X509.X509Certificate[] Chain => this.chain;

        public WebProxy Proxy
        {
            get => this.proxy;
            set => this.proxy = value;
        }

        public DateTime CheckingDateTime
        {
            get => this._checkingDatetime;
            set => this._checkingDatetime = value;
        }

        public bool OnlineCheckingAllowed
        {
            get => this.onlineCheckingAllowed;
            set => this.onlineCheckingAllowed = value;
        }

        public bool CheckingViaOcsp
        {
            get => this.checkingViaOcsp;
            set => this.checkingViaOcsp = value;
        }

        public string[] AdditionalCRLs
        {
            get => this.additionalCRLs;
            set => this.additionalCRLs = value;
        }

        public CertChecker(
          X509Certificate2 cert,
          DateTime checkingDatetime,
          bool onlineCheckingAllowed = true,
          bool checkingViaOcsp = false,
          string[] additionalCRLs = null)
        {
            this._cert = cert;
            this._checkingDatetime = checkingDatetime;
            this.onlineCheckingAllowed = onlineCheckingAllowed;
            this.checkingViaOcsp = checkingViaOcsp;
            this.additionalCRLs = additionalCRLs;
            CertChecker.extraStore = new List<X509Certificate2>();
        }

        internal List<X509Certificate2> GetExternalStore()
        {
            X509Certificate2 x509Certificate2_1 = new X509Certificate2(Resources.VGCA_ROOTCA_BIN);
            X509Certificate2 x509Certificate2_2 = new X509Certificate2(Resources.CP_BIN);
            X509Certificate2 x509Certificate2_3 = new X509Certificate2(Resources.BTC_BIN);
            X509Certificate2 x509Certificate2_4 = new X509Certificate2(Resources.BCA_BIN);
            X509Certificate2 x509Certificate2_5 = new X509Certificate2(Resources.DCS_BIN);
            X509Certificate2 x509Certificate2_6 = new X509Certificate2(Resources.BNG_BIN);
            X509Certificate2 x509Certificate2_7 = new X509Certificate2(Resources.BCY_ROOT_G2);
            X509Certificate2 x509Certificate2_8 = new X509Certificate2(Resources.BCY_CP_G2);
            X509Certificate2 x509Certificate2_9 = new X509Certificate2(Resources.BCY_DCS_G2);
            X509Certificate2 x509Certificate2_10 = new X509Certificate2(Resources.BCY_SS_G2);
            X509Certificate2 x509Certificate2_11 = new X509Certificate2(Resources.MIC_BIN);
            X509Certificate2 x509Certificate2_12 = new X509Certificate2(Resources.VIETTELCA_BIN);
            X509Certificate2 x509Certificate2_13 = new X509Certificate2(Resources.VNPTCA_BIN);
            X509Certificate2 x509Certificate2_14 = new X509Certificate2(Resources.BKAVCA_BIN);
            X509Certificate2 x509Certificate2_15 = new X509Certificate2(Resources.FPTCA_BIN);
            X509Certificate2 x509Certificate2_16 = new X509Certificate2(Resources.CA2_BIN);
            X509Certificate2 x509Certificate2_17 = new X509Certificate2(Resources.NEWTELCA_BIN);
            X509Certificate2 x509Certificate2_18 = new X509Certificate2(Resources.SafeCA_BIN);
            X509Certificate2 x509Certificate2_19 = new X509Certificate2(Resources.SMARTSIGN_BIN);
            X509Certificate2 x509Certificate2_20 = new X509Certificate2(Resources.EFYCA_BIN);
            X509Certificate2 x509Certificate2_21 = new X509Certificate2(Resources.TRUSTCA_BIN);
            CertChecker.extraStore.Add(x509Certificate2_1);
            CertChecker.extraStore.Add(x509Certificate2_7);
            CertChecker.extraStore.Add(x509Certificate2_11);
            CertChecker.extraStore.Add(x509Certificate2_2);
            CertChecker.extraStore.Add(x509Certificate2_3);
            CertChecker.extraStore.Add(x509Certificate2_4);
            CertChecker.extraStore.Add(x509Certificate2_5);
            CertChecker.extraStore.Add(x509Certificate2_6);
            CertChecker.extraStore.Add(x509Certificate2_8);
            CertChecker.extraStore.Add(x509Certificate2_9);
            CertChecker.extraStore.Add(x509Certificate2_10);
            CertChecker.extraStore.Add(x509Certificate2_12);
            CertChecker.extraStore.Add(x509Certificate2_13);
            CertChecker.extraStore.Add(x509Certificate2_14);
            CertChecker.extraStore.Add(x509Certificate2_15);
            CertChecker.extraStore.Add(x509Certificate2_17);
            CertChecker.extraStore.Add(x509Certificate2_18);
            CertChecker.extraStore.Add(x509Certificate2_19);
            CertChecker.extraStore.Add(x509Certificate2_20);
            CertChecker.extraStore.Add(x509Certificate2_21);
            return CertChecker.extraStore;
        }

        internal static List<X509Certificate2> GetCTLStore()
        {
            CertChecker.extraStore = new List<X509Certificate2>();
            X509Certificate2 x509Certificate2_1 = new X509Certificate2(Resources.VGCA_ROOTCA_BIN);
            X509Certificate2 x509Certificate2_2 = new X509Certificate2(Resources.BCY_ROOT_G2);
            X509Certificate2 x509Certificate2_3 = new X509Certificate2(Resources.MIC_BIN);
            X509Certificate2 x509Certificate2_4 = new X509Certificate2(Resources.NCA_ROOT_G2_BIN);
            CertChecker.extraStore.Add(x509Certificate2_1);
            CertChecker.extraStore.Add(x509Certificate2_2);
            CertChecker.extraStore.Add(x509Certificate2_3);
            CertChecker.extraStore.Add(x509Certificate2_4);
            try
            {
                foreach (string cerificate in GCA_CTL.GetCTL().Cerificates)
                {
                    X509Certificate2 x509Certificate2_5 = new X509Certificate2(Convert.FromBase64String(cerificate));
                    CertChecker.extraStore.Add(x509Certificate2_5);
                }
            }
            catch (Exception ex)
            {
                Utils.WriteLog(nameof(GetCTLStore), new Exception("Lỗi định dạng danh sách chứng thư số CA", ex));
            }
            return CertChecker.extraStore;
        }

        public void SetExtraStore(List<X509Certificate2> certs)
        {
            CertChecker.extraStore.AddRange((IEnumerable<X509Certificate2>)certs);
        }

        private string GetCRLCacheDir()
        {
            string path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "VGCA\\crl");
            if (!Directory.Exists(path))
            {
                try
                {
                    Directory.CreateDirectory(path);
                }
                catch
                {
                    path = Path.GetTempPath();
                }
            }
            return path;
        }

        private int CheckValidity()
        {
            if (this._checkingDatetime.CompareTo(this._cert.NotAfter) > 0)
                return 1;
            return this._checkingDatetime.CompareTo(this._cert.NotBefore) < 0 ? 2 : 0;
        }

        private int CheckingCertChain()
        {
            X509ChainPolicy x509ChainPolicy = new X509ChainPolicy();
            x509ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            x509ChainPolicy.VerificationTime = this._checkingDatetime;
            x509ChainPolicy.VerificationFlags = X509VerificationFlags.AllFlags;
            x509ChainPolicy.ExtraStore.AddRange(CertChecker.GetCTLStore().ToArray());
            X509Chain x509Chain = new X509Chain();
            x509Chain.ChainPolicy = x509ChainPolicy;
            if (!x509Chain.Build(this._cert))
                return 3;
            this.chain = new Org.BouncyCastle.X509.X509Certificate[x509Chain.ChainElements.Count];
            X509CertificateParser certificateParser = new X509CertificateParser();
            Org.BouncyCastle.X509.X509Certificate x509Certificate = (Org.BouncyCastle.X509.X509Certificate)null;
            for (int index = 0; index < x509Chain.ChainElements.Count; ++index)
            {
                Org.BouncyCastle.X509.X509Certificate cert = certificateParser.ReadCertificate(x509Chain.ChainElements[index].Certificate.RawData);
                this.chain[index] = cert;
                if (CertInfo.IsSelfSigned(cert))
                    x509Certificate = cert;
            }
            return x509Certificate == null ? 3 : 0;
        }

        private bool VerifyTrustedRoot(Org.BouncyCastle.X509.X509Certificate root)
        {
            X509CertificateParser certificateParser = new X509CertificateParser();
            Org.BouncyCastle.X509.X509Certificate cert1_1 = certificateParser.ReadCertificate(Resources.VGCA_ROOTCA_BIN);
            Org.BouncyCastle.X509.X509Certificate cert1_2 = certificateParser.ReadCertificate(Resources.BCY_ROOT_G2);
            Org.BouncyCastle.X509.X509Certificate cert1_3 = certificateParser.ReadCertificate(Resources.MIC_BIN);
            Org.BouncyCastle.X509.X509Certificate cert1_4 = certificateParser.ReadCertificate(Resources.NCA_ROOT_G2_BIN);
            return CertChecker.ValidRoot(cert1_1, root) || CertChecker.ValidRoot(cert1_2, root) || CertChecker.ValidRoot(cert1_3, root) || CertChecker.ValidRoot(cert1_4, root);
        }

        private static bool ValidRoot(Org.BouncyCastle.X509.X509Certificate cert1, Org.BouncyCastle.X509.X509Certificate cert2)
        {
            try
            {
                cert2.Verify(cert1.GetPublicKey());
                return true;
            }
            catch
            {
                return false;
            }
        }

        private static bool CheckCrl(X509Crl crl, Org.BouncyCastle.X509.X509Certificate issuer, DateTime _time)
        {
            try
            {
                crl.Verify(issuer.GetPublicKey());
                if (crl.NextUpdate.Value.ToLocalTime() < _time)
                    throw new Exception();
                return true;
            }
            catch
            {
                return false;
            }
        }

        private X509Crl GetCacheCrl(string crlPath)
        {
            if (System.IO.File.Exists(crlPath))
            {
                X509CrlParser x509CrlParser = new X509CrlParser();
                FileStream inStream = new FileStream(crlPath, FileMode.Open, FileAccess.Read);
                try
                {
                    return x509CrlParser.ReadCrl((Stream)inStream);
                }
                catch
                {
                }
                finally
                {
                    inStream.Close();
                }
            }
            return (X509Crl)null;
        }

        public static bool DownloadFile(string remoteFilename, string localFilename)
        {
            bool flag = false;
            Stream stream1 = (Stream)null;
            Stream stream2 = (Stream)null;
            WebResponse webResponse = (WebResponse)null;
            try
            {
                WebRequest webRequest = WebRequest.Create(remoteFilename);
                if (webRequest != null)
                {
                    webResponse = webRequest.GetResponse();
                    if (webResponse != null)
                    {
                        stream1 = webResponse.GetResponseStream();
                        stream2 = (Stream)System.IO.File.Create(localFilename);
                        byte[] buffer = new byte[2048];
                        int count;
                        do
                        {
                            count = stream1.Read(buffer, 0, buffer.Length);
                            stream2.Write(buffer, 0, count);
                        }
                        while (count > 0);
                        flag = true;
                    }
                }
            }
            catch (Exception ex)
            {
                Utils.WriteLog(nameof(DownloadFile), ex);
            }
            finally
            {
                webResponse?.Close();
                stream1?.Close();
                stream2?.Close();
            }
            return flag;
        }

        private int CrlChecking(Org.BouncyCastle.X509.X509Certificate cert, Org.BouncyCastle.X509.X509Certificate isserCert)
        {
            List<string> listCrlurl = new List<string>() { CertificateUtil.GetCRLURL(cert) } ;
            if (listCrlurl.Count == 0)
                return 5;
            string path = listCrlurl[0];
            string str = Path.Combine(this.GetCRLCacheDir(), Path.GetFileName(path));
            bool flag1 = false;
            X509Crl cacheCrl;
            do
            {
                cacheCrl = this.GetCacheCrl(str);
                if (!CertChecker.CheckCrl(cacheCrl, isserCert, this._checkingDatetime))
                {
                    if (flag1)
                        return 10;
                    List<string> stringList = new List<string>();
                    stringList.AddRange((IEnumerable<string>)listCrlurl);
                    if (this.additionalCRLs != null && this.additionalCRLs.Length != 0)
                    {
                        foreach (string additionalCrL in this.additionalCRLs)
                        {
                            if (Path.GetFileName(additionalCrL) == Path.GetFileName(path))
                                stringList.Add(additionalCrL);
                        }
                    }
                    bool flag2 = false;
                    foreach (string remoteFilename in stringList)
                    {
                        if (CertChecker.DownloadFile(remoteFilename, str))
                        {
                            flag2 = true;
                            break;
                        }
                        Thread.Sleep(10);
                    }
                    if (!flag2)
                        return 6;
                    flag1 = true;
                }
                else
                    break;
            }
            while (cacheCrl == null || !flag1);
            return cacheCrl.IsRevoked(cert) && cacheCrl.GetRevokedCertificate(cert.SerialNumber).RevocationDate.ToLocalTime() < this._checkingDatetime ? 8 : 0;
        }

        private int CheckingCertRevocation(Org.BouncyCastle.X509.X509Certificate[] chain)
        {
            string str = "";
            if (this.checkingViaOcsp)
            {
                try
                {
                    OcspClient ocspClient = new OcspClient();
                    Org.BouncyCastle.X509.X509Certificate eeCert = new X509CertificateParser().ReadCertificate(this._cert.RawData);
                    Org.BouncyCastle.X509.X509Certificate issuerCert = (Org.BouncyCastle.X509.X509Certificate)null;
                    foreach (Org.BouncyCastle.X509.X509Certificate x509Certificate in chain)
                    {
                        try
                        {
                            eeCert.Verify(x509Certificate.GetPublicKey());
                            issuerCert = x509Certificate;
                            break;
                        }
                        catch
                        {
                        }
                    }
                    switch (ocspClient.Query(eeCert, issuerCert))
                    {
                        case CertificateStatus.Revoked:
                            return 8;
                        case CertificateStatus.Unknown:
                            return 11;
                        default:
                            return 0;
                    }
                }
                catch (Exception ex)
                {
                    str = ex.Message;
                    Utils.WriteLog(nameof(CheckingCertRevocation), ex);
                }
            }
            try
            {
                int index = 0;
                if (index >= chain.Length)
                    return 0;
                Org.BouncyCastle.X509.X509Certificate cert = chain[index];
                Org.BouncyCastle.X509.X509Certificate isserCert = index != chain.Length - 1 ? chain[index + 1] : cert;
                int num = this.CrlChecking(cert, isserCert);
                return num == 8 && index != 0 ? 9 : num;
            }
            catch (Exception ex)
            {
                if (!string.IsNullOrEmpty(str))
                    throw new Exception(string.Format("CheckingCertRevocation: {0}. {1}", (object)str, (object)ex.Message), ex);
                throw ex;
            }
        }

        public int Check()
        {
            int num1 = this.CheckValidity();
            if (num1 != 0)
                return num1;
            int num2 = this.CheckingCertChain();
            if (num2 != 0)
                return num2;
            return this.onlineCheckingAllowed ? this.CheckingCertRevocation(this.chain) : 7;
        }
    }
}
