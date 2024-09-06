using Nancy.Json;


namespace VGCA
{
    public class GCA_CTL
    {
        public const string GCA_CTL_URL = "http://ca.gov.vn/pki/pub/ctl/gca.ctl";

        public int Version { get; set; }

        public string ListIdentifier { get; set; }

        public int SequenceNumber { get; set; }

        public DateTime ThisUpdate { get; set; }

        public DateTime NextUpdate { get; set; }

        public List<string> Cerificates { get; set; }

        private static string GetCTLCacheDir()
        {
            string path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "VGCA\\ctl");
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

        private static GCA_CTL? GetCacheCtl()
        {
            string path = Path.Combine(GCA_CTL.GetCTLCacheDir(), Path.GetFileName("http://ca.gov.vn/pki/pub/ctl/gca.ctl"));
            return File.Exists(path) ? new JavaScriptSerializer().Deserialize<GCA_CTL>(File.ReadAllText(path)) : (GCA_CTL)null;
        }

        public static GCA_CTL GetCTL()
        {
            string localFilename = Path.Combine(GCA_CTL.GetCTLCacheDir(), Path.GetFileName("http://ca.gov.vn/pki/pub/ctl/gca.ctl"));
            GCA_CTL cacheCtl = GCA_CTL.GetCacheCtl();
            if (cacheCtl == null)
            {
                if (!CertChecker.DownloadFile("http://ca.gov.vn/pki/pub/ctl/gca.ctl", localFilename))
                    throw new Exception("Lỗi tải danh sách chứng thư số CA. Kiểm tra lại kết nối mạng. (0x0031)");
                cacheCtl = GCA_CTL.GetCacheCtl();
            }
            return cacheCtl;
        }
    }
}
