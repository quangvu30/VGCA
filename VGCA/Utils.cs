using iTextSharp.text.pdf.security;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1;
using System.Net;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using System.Text;


namespace VGCA
{
    public static class Utils
    {
        public static string ASM_VERSION = "3.0.18";
        internal static readonly string LOG_URL = "http://gscts.dcs.vn/monitoring.ashx";
        internal static string ROOTCA_CERTIFICATE = "-----BEGIN CERTIFICATE-----MIID+DCCAuCgAwIBAgIJAP8wOuTpCsHtMA0GCSqGSIb3DQEBBQUAMGsxCzAJBgNVBAYTAlZOMR0wGwYDVQQKDBRCYW4gQ28geWV1IENoaW5oIHBodTE9MDsGA1UEAww0Q28gcXVhbiBjaHVuZyB0aHVjIHNvIGNodXllbiBkdW5nIENoaW5oIHBodSAoUm9vdENBKTAeFw0xMDAzMTAwNTQ1NTdaFw0zMDAzMDUwNTQ1NTdaMGsxCzAJBgNVBAYTAlZOMR0wGwYDVQQKDBRCYW4gQ28geWV1IENoaW5oIHBodTE9MDsGA1UEAww0Q28gcXVhbiBjaHVuZyB0aHVjIHNvIGNodXllbiBkdW5nIENoaW5oIHBodSAoUm9vdENBKTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANrzvexkvgul4dRUnV6GMcvLdenKrrzYnVpzIp78ijBMqWcG+cu+AJS2GbqYdbsO6JnaNLSxuxpM7Uejiwi2QBTe2NXIy4TtkadbIjPlQHUIetTYeLTESUw0vOEuwtAM2PVmoSpdEPFw4o06E3/MCtiM0fSRuyyXM8uu0EyYqUowFJbEDERqqlPeU0okutsgzUFtZkG/TM6WE97FMbA4KC5stxG8SHCe4YFNrQIaM8Ozemd11MIJaSHSvrv+EWR1TDeg02U18qB3aiaamSX2M7B3JMKedOoBo1UQkLc/ePqG2kKHVbc2p1mePX5n1etCpM6+RUjpzvdkcihxxAUjJAcCAwEAAaOBnjCBmzAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTZFxtRoxe3nvwt22H6eQD/WHSdXDAfBgNVHSMEGDAWgBTZFxtRoxe3nvwt22H6eQD/WHSdXDAOBgNVHQ8BAf8EBAMCAQYwOAYDVR0fBDEwLzAtoCugKYYnaHR0cDovL2NhLmdvdi52bi9wa2kvcHViL2NybC9yb290Y2EuY3JsMA0GCSqGSIb3DQEBBQUAA4IBAQAbivpvhtC3w/9gWAh34UovGuSUwFDQOcmUTExhhJiADI18E49WBTeN1iC7oZhb1aFRQzW9e6NNgkSrCy5pik1gkdOtgB+qx2b3s9CCj8VNywlADH9ziMmXPgyJLv0n9TqBj7yTWT85Yc49er0nsDdvxSBqlJiiu/SGD6ZMda/mztJnkrteTAka2zw2i46rcwTSURjyYEJfpj/joxEcCqAubXwIdteNWjMhz07MrPXDa7OGdn7ppLpZEIHmSCZR+ULILtrd3cTDAzRlIP9bNzg1wc0bf4IY9ErVFZAPlnx6wxxIIOWp+JBRpf1TiKu73Q990Pmcpk92bAk68y20xRIl-----END CERTIFICATE-----";
        internal static string CRL_DIRECTORY = string.Format("{0}\\VGCA\\crl", (object)Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData));

        public static string ToLogString(Exception ex)
        {
            StringBuilder stringBuilder = new StringBuilder();
            if (ex != null)
            {
                Exception exception = ex;
                stringBuilder.Append("Exception:");
                stringBuilder.Append(Environment.NewLine);
                for (; exception != null; exception = exception.InnerException)
                {
                    stringBuilder.Append(exception.Message);
                    stringBuilder.Append(Environment.NewLine);
                }
                if (ex.Data != null)
                {
                    foreach (object obj in ex.Data)
                    {
                        stringBuilder.Append("Data :");
                        stringBuilder.Append(obj.ToString());
                        stringBuilder.Append(Environment.NewLine);
                    }
                }
                if (ex.StackTrace != null)
                {
                    stringBuilder.Append("StackTrace:");
                    stringBuilder.Append(Environment.NewLine);
                    stringBuilder.Append(ex.StackTrace.ToString());
                    stringBuilder.Append(Environment.NewLine);
                }
                if (ex.Source != null)
                {
                    stringBuilder.Append("Source:");
                    stringBuilder.Append(Environment.NewLine);
                    stringBuilder.Append(ex.Source);
                    stringBuilder.Append(Environment.NewLine);
                }
                if (ex.TargetSite != (MethodBase)null)
                {
                    stringBuilder.Append("TargetSite:");
                    stringBuilder.Append(Environment.NewLine);
                    stringBuilder.Append(ex.TargetSite.ToString());
                    stringBuilder.Append(Environment.NewLine);
                }
                if (ex.GetBaseException() != null)
                {
                    stringBuilder.Append("BaseException:");
                    stringBuilder.Append(Environment.NewLine);
                    stringBuilder.Append((object)ex.GetBaseException());
                }
            }
            return stringBuilder.ToString();
        }

        public static void WriteLog(string msg, Exception ex)
        {
            try
            {
                string path = string.Format("{0}\\VGCA\\Pdf\\log.txt", (object)Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData));
                DirectoryInfo directoryInfo = new DirectoryInfo(Path.GetDirectoryName(path));
                if (!directoryInfo.Exists)
                    directoryInfo.Create();
                if (!new DirectoryInfo(Path.GetDirectoryName(path)).Exists)
                    return;
                string contents = string.Format("{0}{1}{0}=========={2}============{0}{3}", (object)Environment.NewLine, (object)msg, (object)DateTime.Now.ToString(), (object)Utils.ToLogString(ex));
                System.IO.File.AppendAllText(path, contents);
            }
            catch
            {
            }
        }

        public static void SIGN_GMON_v1(X509Certificate2 signer)
        {
            try
            {
                string uriString = string.Format("{0}{1}/{2}", (object)"http://ca.gov.vn/gmon/vSignPDF-v", (object)Utils.ASM_VERSION, (object)signer.SerialNumber);
                using (WebClient webClient = new WebClient())
                    webClient.DownloadStringAsync(new Uri(uriString));
            }
            catch (Exception ex)
            {
                Utils.WriteLog(nameof(SIGN_GMON_v1), ex);
            }
        }
    }
}
