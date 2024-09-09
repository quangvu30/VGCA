using iTextSharp.awt.geom;
using iTextSharp.text.pdf.security;
using iTextSharp.text.pdf;
using iTextSharp.text;
using Org.BouncyCastle.X509;
using System.Globalization;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Security;

namespace VGCA
{
    public class PdfSigner
    {
        private object thisLock = new object();
        private string _inputPdf;
        private string _outputPdf;
        private X509Certificate2 _cert;
        private Org.BouncyCastle.X509.X509Certificate[] _encCerts;
        private string _reason;
        private string _location;
        private bool _usedTsa;
        private string _tsaUrl;
        private bool _usedProxy;
        private WebProxy _proxy;
        private System.Drawing.Image _signatureImage;
        private PdfSignatureAppearance.RenderingMode sigAppr = PdfSignatureAppearance.RenderingMode.GRAPHIC_AND_DESCRIPTION;
        private bool showLabel = true;
        private bool showEmail = true;
        private bool showCQ1 = true;
        private bool showCQ2 = true;
        private bool showDate = true;
        private bool showCQ3 = true;
        private bool isOrgProfile;
        private string _job;
        private const float MARGIN = 0.0f;
        private const float TOP_SECTION = 0.0f;

        public string InputPdf
        {
            get => this._inputPdf;
            set => this._inputPdf = value;
        }

        public string OutputPdf
        {
            get => this._outputPdf;
            set => this._outputPdf = value;
        }

        public X509Certificate2 Cert
        {
            get => this._cert;
            set => this._cert = value;
        }

        public X509Certificate2[] Recipients
        {
            get
            {
                if (this._encCerts == null)
                    return (X509Certificate2[])null;
                X509Certificate2[] recipients = new X509Certificate2[this._encCerts.Length];
                for (int index = 0; index < this._encCerts.Length; ++index)
                {
                    X509Certificate2 x509Certificate2 = new X509Certificate2(this._encCerts[index].GetEncoded());
                    recipients[index] = x509Certificate2;
                }
                return recipients;
            }
            set
            {
                if (value == null)
                    this._encCerts = (Org.BouncyCastle.X509.X509Certificate[])null;
                this._encCerts = new Org.BouncyCastle.X509.X509Certificate[value.Length];
                X509CertificateParser certificateParser = new X509CertificateParser();
                for (int index = 0; index < value.Length; ++index)
                {
                    X509Certificate2 x509Certificate2 = value[index];
                    this._encCerts[index] = certificateParser.ReadCertificate(x509Certificate2.RawData);
                }
            }
        }

        public string Reason
        {
            get => this._reason;
            set => this._reason = value;
        }

        public string Location
        {
            get => this._location;
            set => this._location = value;
        }

        public bool UsedTsa
        {
            get => this._usedTsa;
            set => this._usedTsa = value;
        }

        public string TsaUrl
        {
            get => this._tsaUrl;
            set => this._tsaUrl = value;
        }

        public bool UsedProxy
        {
            get => this._usedProxy;
            set => this._usedProxy = value;
        }

        public WebProxy Proxy
        {
            get => this._proxy;
            set => this._proxy = value;
        }

        public System.Drawing.Image SignatureImage
        {
            get => this._signatureImage;
            set => this._signatureImage = value;
        }

        public PdfSignatureAppearance.RenderingMode SignatureAppearance
        {
            get => this.sigAppr;
            set => this.sigAppr = value;
        }

        public bool ShowLabel
        {
            get => this.showLabel;
            set => this.showLabel = value;
        }

        public bool ShowEmail
        {
            get => this.showEmail;
            set => this.showEmail = value;
        }

        public bool ShowCQ1
        {
            get => this.showCQ1;
            set => this.showCQ1 = value;
        }

        public bool ShowCQ2
        {
            get => this.showCQ2;
            set => this.showCQ2 = value;
        }

        public bool ShowDate
        {
            get => this.showDate;
            set => this.showDate = value;
        }

        public bool ShowCQ3
        {
            get => this.showCQ3;
            set => this.showCQ3 = value;
        }

        public bool IsOrgProfile
        {
            get => this.isOrgProfile;
            set => this.isOrgProfile = value;
        }

        public string Job
        {
            get => this._job;
            set => this._job = value;
        }

        public PdfSigner(string inputPdf, string ouputPdf, X509Certificate2 cert)
        {
            this._inputPdf = inputPdf;
            this._outputPdf = ouputPdf;
            this._cert = cert;
            this._usedTsa = false;
            this._tsaUrl = (string)null;
            this._proxy = (WebProxy)null;
        }

        private string GetSignatureText()
        {
            CertInfo certInfo = new CertInfo(this._cert);
            StringBuilder stringBuilder = new StringBuilder();
            string commonName = certInfo.CommonName;
            string email = certInfo.Email;
            string str = "";
            if (this.showCQ3 && certInfo.OUs.Count > 0)
                str = certInfo.OUs[0];
            if (this.showCQ2 && certInfo.OUs.Count > 1)
            {
                if (!string.IsNullOrEmpty(str))
                    str += ", ";
                string ou;
                str += ou = certInfo.OUs[1];
            }
            if (this.showCQ1)
            {
                if (!string.IsNullOrEmpty(str))
                    str += ", ";
                str += certInfo.O;
            }
            if (this.isOrgProfile)
            {
                if (this.showLabel)
                {
                    stringBuilder.Append("Cơ quan: ");
                    stringBuilder.Append(commonName);
                    if (!string.IsNullOrEmpty(str))
                    {
                        stringBuilder.Append(", ");
                        stringBuilder.Append(str);
                    }
                    if (this.showEmail && !string.IsNullOrEmpty(email))
                    {
                        stringBuilder.Append(Environment.NewLine);
                        stringBuilder.Append("Email: ");
                        stringBuilder.Append(email);
                    }
                    if (this.showDate)
                    {
                        stringBuilder.Append(Environment.NewLine);
                        stringBuilder.Append("Thời gian ký: ");
                        stringBuilder.Append(DateTime.Now.ToString("dd.MM.yyyy HH:mm:ss zzz", (IFormatProvider)CultureInfo.CreateSpecificCulture("en-US")));
                    }
                }
                else
                {
                    stringBuilder.Append(commonName);
                    if (!string.IsNullOrEmpty(str))
                    {
                        stringBuilder.Append(", ");
                        stringBuilder.Append(str);
                    }
                    if (this.showEmail && !string.IsNullOrEmpty(email))
                    {
                        stringBuilder.Append(Environment.NewLine);
                        stringBuilder.Append(email);
                    }
                    if (this.showDate)
                    {
                        stringBuilder.Append(Environment.NewLine);
                        stringBuilder.Append(DateTime.Now.ToString("dd.MM.yyyy HH:mm:ss zzz", (IFormatProvider)CultureInfo.CreateSpecificCulture("en-US")));
                    }
                }
            }
            else if (this.showLabel)
            {
                stringBuilder.Append("Người ký: " + commonName);
                if (this.showEmail && !string.IsNullOrEmpty(email))
                {
                    stringBuilder.Append(Environment.NewLine);
                    stringBuilder.Append("Email: ");
                    stringBuilder.Append(email);
                }
                if (!string.IsNullOrEmpty(str))
                {
                    stringBuilder.Append(Environment.NewLine);
                    stringBuilder.Append("Cơ quan: ");
                    stringBuilder.Append(str);
                }
                if (this.showCQ3 && !string.IsNullOrEmpty(this._job))
                {
                    stringBuilder.Append(Environment.NewLine);
                    stringBuilder.Append("Chức vụ: ");
                    stringBuilder.Append(this._job);
                }
                if (this.showDate)
                {
                    stringBuilder.Append(Environment.NewLine);
                    stringBuilder.Append("Thời gian ký: ");
                    stringBuilder.Append(DateTime.Now.ToString("dd.MM.yyyy HH:mm:ss zzz", (IFormatProvider)CultureInfo.CreateSpecificCulture("en-US")));
                }
            }
            else
            {
                stringBuilder.Append(commonName);
                if (this.showEmail && !string.IsNullOrEmpty(email))
                {
                    stringBuilder.Append(Environment.NewLine);
                    stringBuilder.Append(email);
                }
                if (!string.IsNullOrEmpty(str))
                {
                    stringBuilder.Append(Environment.NewLine);
                    stringBuilder.Append(str);
                }
                if (this.showCQ3 && !string.IsNullOrEmpty(this._job))
                {
                    stringBuilder.Append(Environment.NewLine);
                    stringBuilder.Append(this._job);
                }
                if (this.showDate)
                {
                    stringBuilder.Append(Environment.NewLine);
                    stringBuilder.Append(DateTime.Now.ToString("dd.MM.yyyy HH:mm:ss zzz", (IFormatProvider)CultureInfo.CreateSpecificCulture("en-US")));
                }
            }
            return stringBuilder.ToString();
        }


        public void Sign(int iPage, int llx, int lly, int iWidth, int iHeight, int rotation)
        {
            FileStream os = (FileStream)null;
            try
            {
                if (this._cert == null)
                    throw new Exception("Không có chứng thư số ký");
                if (!System.IO.File.Exists(this._inputPdf))
                    throw new Exception("Tệp đầu vào không tồn tại");
                lock (this.thisLock)
                {
                    Org.BouncyCastle.X509.X509Certificate[] chain = new Org.BouncyCastle.X509.X509Certificate[1]
                    {
            new X509CertificateParser().ReadCertificate(this._cert.RawData)
                    };
                    PdfReader reader = new PdfReader(this._inputPdf);
                    if (reader.IsEncrypted())
                    {
                        reader.Close();
                        throw new Exception("Tài liệu pdf đã được mã hóa");
                    }
                    try
                    {
                        os = new FileStream(this._outputPdf, FileMode.Create);
                    }
                    catch (SecurityException ex)
                    {
                        throw new Exception("Không có quyền truy cập đường dẫn lưu tệp ký số");
                    }
                    catch (IOException ex)
                    {
                        throw new Exception("Đường dẫn lưu tệp ký số không hợp lệ");
                    }
                    int num = reader.AcroFields.GetSignatureNames().Count > 0 ? 1 : 0;
                    PdfSignatureAppearance signatureAppearance = PdfStamper.CreateSignature(reader, (Stream)os, char.MinValue, (string)null, true).SignatureAppearance;
                    signatureAppearance.SetVisibleSignature(new iTextSharp.text.Rectangle((float)llx, (float)lly, (float)(llx + iWidth), (float)(lly + iHeight)), iPage, signatureAppearance.GetNewSigName());
                    signatureAppearance.SignatureRenderingMode = this.sigAppr;
                    signatureAppearance.SignDate = DateTime.Now;
                    signatureAppearance.Reason = this._reason;
                    signatureAppearance.Location = this._location;
                    signatureAppearance.Acro6Layers = true;
                    if (num == 0)
                        signatureAppearance.CertificationLevel = 2;
                    CertInfo certInfo = new CertInfo(this._cert.RawData);
                    string signatureText = this.GetSignatureText();
                    float size = 5f;
                    BaseFont font1 = BaseFont.CreateFont("times.ttf", "Identity-H", true, true, Resources.times, (byte[])null);
                    font1.Subset = true;
                    iTextSharp.text.Font font2 = new iTextSharp.text.Font(font1, size, 0);
                    iTextSharp.text.Rectangle rect = new iTextSharp.text.Rectangle((float)llx, (float)lly, (float)(llx + iWidth - 2), (float)(lly + iHeight - 2));
                    if (this.sigAppr != PdfSignatureAppearance.RenderingMode.DESCRIPTION)
                        signatureAppearance.SignatureGraphic = iTextSharp.text.Image.GetInstance(this._signatureImage, this._signatureImage.RawFormat);
                    ColumnText.FitText(font2, signatureText, rect, 70f, 1);
                    signatureAppearance.Layer2Text = signatureText;
                    signatureAppearance.Layer2Font = font2;
                    try
                    {
                        this.CustomizeSignatureAppearance(signatureAppearance, rect, rotation);
                    }
                    catch (Exception ex)
                    {
                        Utils.WriteLog("CustomizeSignatureAppearance", ex);
                        throw ex;
                    }
                    ITSAClient tsaClient = (ITSAClient)null;
                    if (this._usedTsa && !string.IsNullOrEmpty(this._tsaUrl))
                    {
                        TSAClientBouncyCastle clientBouncyCastle = new TSAClientBouncyCastle(this._tsaUrl, (string)null, (string)null, 4096, "SHA1");
                        if (this._usedProxy)
                            clientBouncyCastle.Proxy = this._proxy;
                        tsaClient = (ITSAClient)clientBouncyCastle;
                    }
                    X509Signature x509Signature = new X509Signature(this._cert, "SHA-256");
                    try
                    {
                        MakeSignature.SignDetached(signatureAppearance, (IExternalSignature)x509Signature, (ICollection<Org.BouncyCastle.X509.X509Certificate>)chain, (ICollection<ICrlClient>)null, (IOcspClient)null, tsaClient, 0, CryptoStandard.CMS);
                        Utils.SIGN_GMON_v1(this._cert);
                    }
                    catch (Exception ex)
                    {
                        Utils.WriteLog("SignDetached", ex);
                        throw new Exception("Ký số không thành công: " + ex.Message, ex);
                    }
                }
            }
            catch (Exception ex)
            {
                os?.Close();
                if (System.IO.File.Exists(this._outputPdf))
                {
                    try
                    {
                        System.IO.File.Delete(this._outputPdf);
                    }
                    catch
                    {
                    }
                }
                throw ex;
            }
            finally
            {
                os?.Close();
            }
        }

        private void CustomizeSignatureAppearance(
          PdfSignatureAppearance sap,
          iTextSharp.text.Rectangle rect,
          int rotation)
        {
            iTextSharp.text.Rectangle rectangle1 = (iTextSharp.text.Rectangle)null;
            iTextSharp.text.Rectangle rectangle2 = (iTextSharp.text.Rectangle)null;
            float num1 = rect.Width;
            float ury = rect.Height;
            AffineTransform af = new AffineTransform();
            switch (rotation)
            {
                case 1:
                    num1 = rect.Height;
                    ury = rect.Width;
                    af = new AffineTransform(0.0f, 1f, -1f, 0.0f, rect.Width, 0.0f);
                    break;
                case 2:
                    af = new AffineTransform(-1f, 0.0f, 0.0f, -1f, rect.Width, rect.Height);
                    break;
                case 3:
                    num1 = rect.Height;
                    ury = rect.Width;
                    af = new AffineTransform(0.0f, -1f, 1f, 0.0f, 0.0f, rect.Height);
                    break;
            }
            if (sap.SignatureRenderingMode == PdfSignatureAppearance.RenderingMode.NAME_AND_DESCRIPTION || sap.SignatureRenderingMode == PdfSignatureAppearance.RenderingMode.GRAPHIC_AND_DESCRIPTION && sap.SignatureGraphic != null)
            {
                rectangle2 = new iTextSharp.text.Rectangle(0.0f, 0.0f, (float)((double)num1 / 2.0 - 0.0), ury - 0.0f);
                rectangle1 = new iTextSharp.text.Rectangle((float)((double)num1 / 2.0 + 0.0), 0.0f, num1 - 0.0f, ury - 0.0f);
                if ((double)ury > (double)num1)
                {
                    rectangle2 = new iTextSharp.text.Rectangle(0.0f, ury / 2f, num1 - 0.0f, ury);
                    rectangle1 = new iTextSharp.text.Rectangle(0.0f, 0.0f, num1 - 0.0f, (float)((double)ury / 2.0 - 0.0));
                }
            }
            else if (sap.SignatureRenderingMode == PdfSignatureAppearance.RenderingMode.GRAPHIC)
                rectangle2 = new iTextSharp.text.Rectangle(0.0f, 0.0f, num1 - 0.0f, ury - 0.0f);
            else
                rectangle1 = new iTextSharp.text.Rectangle(0.0f, 0.0f, num1 - 0.0f, (float)((double)ury * 1.0 - 0.0));
            PdfTemplate layer = sap.GetLayer(2);
            if (rotation != 0)
                layer.Transform(af);
            if (sap.SignatureRenderingMode == PdfSignatureAppearance.RenderingMode.GRAPHIC_AND_DESCRIPTION)
            {
                ColumnText columnText = new ColumnText((PdfContentByte)layer);
                columnText.RunDirection = 1;
                columnText.SetSimpleColumn(rectangle2.Left, rectangle2.Bottom, rectangle2.Right, rectangle2.Top, 0.0f, 5);
                iTextSharp.text.Image signatureGraphic = sap.SignatureGraphic;
                signatureGraphic.ScaleToFit(rectangle2.Width, rectangle2.Height);
                Paragraph paragraph = new Paragraph();
                float num2 = 0.0f;
                float num3 = (float)(-(double)signatureGraphic.ScaledHeight + 15.0);
                float num4 = num2 + (float)(((double)rectangle2.Width - (double)signatureGraphic.ScaledWidth) / 2.0);
                float offsetY = num3 - (float)(((double)rectangle2.Height - (double)signatureGraphic.ScaledHeight) / 2.0);
                paragraph.Add((IElement)new Chunk(signatureGraphic, num4 + (float)(((double)rectangle2.Width - (double)signatureGraphic.ScaledWidth) / 2.0), offsetY, false));
                columnText.AddElement((IElement)paragraph);
                columnText.Go();
            }
            else if (sap.SignatureRenderingMode == PdfSignatureAppearance.RenderingMode.GRAPHIC)
            {
                ColumnText columnText = new ColumnText((PdfContentByte)layer);
                columnText.RunDirection = 1;
                columnText.SetSimpleColumn(rectangle2.Left, rectangle2.Bottom, rectangle2.Right, rectangle2.Top, 0.0f, 5);
                iTextSharp.text.Image signatureGraphic = sap.SignatureGraphic;
                signatureGraphic.ScaleToFit(rectangle2.Width, rectangle2.Height);
                Paragraph paragraph = new Paragraph(rectangle2.Height);
                float offsetX = (float)(((double)rectangle2.Width - (double)signatureGraphic.ScaledWidth) / 2.0);
                float offsetY = (float)(((double)rectangle2.Height - (double)signatureGraphic.ScaledHeight) / 2.0);
                paragraph.Add((IElement)new Chunk(signatureGraphic, offsetX, offsetY, false));
                columnText.AddElement((IElement)paragraph);
                columnText.Go();
            }
            float calculatedSize = sap.Layer2Font.CalculatedSize;
            if (sap.SignatureRenderingMode == PdfSignatureAppearance.RenderingMode.GRAPHIC)
                return;
            iTextSharp.text.Rectangle rect1 = new iTextSharp.text.Rectangle(rectangle1.Width, rectangle1.Height);
            float leading = ColumnText.FitText(sap.Layer2Font, sap.Layer2Text, rect1, 70f, 1);
            ColumnText columnText1 = new ColumnText((PdfContentByte)layer);
            columnText1.RunDirection = 1;
            columnText1.SetSimpleColumn(new Phrase(sap.Layer2Text, sap.Layer2Font), rectangle1.Left, rectangle1.Bottom, rectangle1.Right, rectangle1.Top, leading, 0);
            columnText1.Go();
        }
    }
}
