using System.Security.Cryptography.X509Certificates;


namespace VGCA
{
    public class CertInfo
    {
        private X509Certificate2 _cert;

        public X509Certificate2 X509 => this._cert;

        public string Thumbprint => this._cert.Thumbprint;

        public string IssuerName => this._cert.GetNameInfo(X509NameType.SimpleName, true);

        public string O
        {
            get
            {
                string[] strArray = this._cert.Subject.Split(new char[1]
                {
          ','
                }, StringSplitOptions.RemoveEmptyEntries);
                string o = string.Empty;
                for (int index = 0; index < strArray.Length; ++index)
                {
                    string str = strArray[index].Trim();
                    if (str.IndexOf("O=") == 0)
                    {
                        o = str.Substring(2);
                        break;
                    }
                }
                return o;
            }
        }

        public string OU
        {
            get
            {
                string[] strArray = this._cert.Subject.Split(new char[1]
                {
          ','
                }, StringSplitOptions.RemoveEmptyEntries);
                string ou = string.Empty;
                for (int index = 0; index < strArray.Length; ++index)
                {
                    string str = strArray[index].Trim();
                    if (str.IndexOf("OU=") == 0)
                        ou = !string.IsNullOrEmpty(ou) ? str.Substring(3) + ", " + ou : str.Substring(3);
                }
                return ou;
            }
        }

        public List<string> OUs
        {
            get
            {
                string[] strArray = this._cert.Subject.Split(new char[1]
                {
          ','
                }, StringSplitOptions.RemoveEmptyEntries);
                List<string> ous = new List<string>();
                for (int index = 0; index < strArray.Length; ++index)
                {
                    string str = strArray[index].Trim();
                    if (str.IndexOf("OU=") == 0)
                        ous.Add(str.Substring(3));
                }
                return ous;
            }
        }

        public string Email => this._cert.GetNameInfo(X509NameType.EmailName, false);

        public string Period
        {
            get
            {
                DateTime dateTime = this._cert.NotBefore;
                string str1 = dateTime.ToString("dd/MM/yyyy");
                dateTime = this._cert.NotAfter;
                string str2 = dateTime.ToString("dd/MM/yyyy");
                return string.Format("{0} đến {1}", (object)str1, (object)str2);
            }
        }

        public string CommonName => this._cert.GetNameInfo(X509NameType.SimpleName, false);

        public string Surname
        {
            get
            {
                string[] strArray = this._cert.Subject.Split(new char[1]
                {
          ','
                }, StringSplitOptions.RemoveEmptyEntries);
                string surname = string.Empty;
                for (int index = 0; index < strArray.Length; ++index)
                {
                    string str = strArray[index].Trim();
                    if (str.IndexOf("SN=") == 0)
                    {
                        surname = str.Substring(3);
                        break;
                    }
                }
                return surname;
            }
        }

        public X509KeyUsageFlags KeyUsages
        {
            get
            {
                X509KeyUsageExtension extension = (X509KeyUsageExtension)this._cert.Extensions["2.5.29.15"];
                return extension != null ? extension.KeyUsages : X509KeyUsageFlags.None;
            }
        }

        public CertInfo(byte[] rawData) => this._cert = new X509Certificate2(rawData);

        public CertInfo(X509Certificate2 cert) => this._cert = cert;

        public override string ToString()
        {
            return string.IsNullOrEmpty(this.Email) ? this.CommonName : string.Format("{0}<{1}>", (object)this.CommonName, (object)this.Email);
        }

        public static bool IsSelfSigned(Org.BouncyCastle.X509.X509Certificate cert)
        {
            try
            {
                if (!cert.SubjectDN.Equivalent(cert.IssuerDN))
                    return false;
                cert.Verify(cert.GetPublicKey());
                return true;
            }
            catch
            {
                return false;
            }
        }

        public static bool IsCertificateAvailable(X509Certificate2 cert) => true;
    }
}
