using iTextSharp.text.pdf;
using iTextSharp.text.pdf.security;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Tsp;
using Org.BouncyCastle.X509.Store;
using System.Collections;
using System.Drawing;
using System.Net;
using System.Reflection.PortableExecutable;
using System.Security.Cryptography.X509Certificates;
using VGCA;

/*
PdfVerifier pdfVerifier = new PdfVerifier("C:\\Users\\quangvd.MXV-VN\\Documents\\Research\\VGCA\\VGCA\\bin\\Debug\\net6.0\\gpkd_signed.pdf");
List<PDFSignatureInfo> info =  pdfVerifier.Verify();
Logger.LogSignatureInfoList(info);
*/

// Console.WriteLine(Resources.VGCA_ROOTCA_BIN);

public class PdfVerifier
{
    private string fileName;
    private bool allowedOnlineChecking;
    private string[] additionalCRLs;
    private X509Certificate2[] additionalCerts;
    private WebProxy proxy;
    private SignatureValidity verifyResult;

    public bool AllowedOnlineChecking
    {
        get => this.allowedOnlineChecking;
        set => this.allowedOnlineChecking = value;
    }

    public string[] AdditionalCRLs
    {
        get => this.additionalCRLs;
        set => this.additionalCRLs = value;
    }

    public X509Certificate2[] AdditionalCerts
    {
        get => this.additionalCerts;
        set => this.additionalCerts = value;
    }

    public WebProxy Proxy
    {
        get => this.proxy;
        set => this.proxy = value;
    }

    public SignatureValidity VerifyResult => this.verifyResult;

    public PdfVerifier(string fileName) => this.fileName = fileName;

    private static List<PDFSignatureInfo> GetSignatures(string filename)
    {
        List<PDFSignatureInfo> signatures = new List<PDFSignatureInfo>();
        PdfReader pdfReader = (PdfReader)null;
        try
        {
            pdfReader = new PdfReader(filename);
            AcroFields acroFields = pdfReader.AcroFields;
            List<string> signatureNames = acroFields.GetSignatureNames();
            for (int index = 0; index < signatureNames.Count; ++index)
            {
                PDFSignatureInfo pdfSignatureInfo = new PDFSignatureInfo();
                string name = signatureNames[index];
                pdfSignatureInfo.SignatureName = name;
                pdfSignatureInfo.SignatureCoversWholeDocument = acroFields.SignatureCoversWholeDocument(name);
                AcroFields.FieldPosition fieldPosition = acroFields.GetFieldPositions(name)[0];
                pdfSignatureInfo.Position = new Rectangle((int)fieldPosition.position.Left, (int)fieldPosition.position.Top, (int)fieldPosition.position.Width, (int)fieldPosition.position.Height);
                pdfSignatureInfo.PageIndex = fieldPosition.page;
                signatures.Add(pdfSignatureInfo);
            }
            return signatures;
        }
        catch (Exception ex)
        {
            throw new Exception("Lỗi định dạng tệp", ex);
        }
        finally
        {
            pdfReader?.Close();
        }
    }

    public static Org.BouncyCastle.X509.X509Certificate GetCertificate(
      SignerInformation signer,
      IX509Store cmsCertificates)
    {
        Org.BouncyCastle.X509.X509Certificate certificate = (Org.BouncyCastle.X509.X509Certificate)null;
        IList list = (IList)new ArrayList(cmsCertificates.GetMatches((IX509Selector)new X509CertStoreSelector()
        {
            Issuer = signer.SignerID.Issuer,
            SerialNumber = signer.SignerID.SerialNumber
        }));
        if (list.Count > 0)
            certificate = (Org.BouncyCastle.X509.X509Certificate)list[0];
        return certificate;
    }

    private int GetEOFCount(Stream fn)
    {
        PRTokeniser prTokeniser = new PRTokeniser(new RandomAccessFileOrArray(fn));
        int eofCount = 0;
        try
        {
            prTokeniser.Seek(0L);
            byte[] numArray = new byte[5];
            while (true)
            {
                long filePointer1;
                do
                {
                    filePointer1 = prTokeniser.FilePointer;
                    if (!prTokeniser.ReadLineSegment(numArray))
                        goto label_6;
                }
                while (numArray[0] != (byte)37 || !PdfEncodings.ConvertToString(numArray, (string)null).StartsWith("%%EOF"));
                ++eofCount;
                prTokeniser.Seek(filePointer1);
                prTokeniser.NextToken();
                long filePointer2 = prTokeniser.FilePointer;
            }
        }
        finally
        {
            prTokeniser.Close();
        }
    label_6:
        return eofCount;
    }

    public List<PDFSignatureInfo> Verify()
    {
        this.verifyResult = SignatureValidity.None;
        List<PDFSignatureInfo> pdfSignatureInfoList = new List<PDFSignatureInfo>();
        PdfReader pdfReader = (PdfReader)null;
        try
        {
            bool flag1 = false;
            bool flag2 = false;
            List<int> intList = new List<int>();
            pdfReader = new PdfReader(this.fileName);
            AcroFields acroFields = pdfReader.AcroFields;
            List<string> signatureNames = acroFields.GetSignatureNames();
            if (signatureNames.Count == 0)
            {
                this.verifyResult = SignatureValidity.NotSigned;
                return pdfSignatureInfoList;
            }
            for (int index = 0; index < signatureNames.Count; ++index)
            {
                PDFSignatureInfo pdfSignatureInfo = new PDFSignatureInfo();
                pdfSignatureInfo.ValidityErrors = new Dictionary<SignatureValidity, string>();
                string str1 = signatureNames[index];
                pdfSignatureInfo.SignatureName = str1;
                try
                {
                    SignatureValidity s1 = SignatureValidity.None;
                    DateTime minValue = DateTime.MinValue;
                    pdfSignatureInfo.SignatureCoversWholeDocument = acroFields.SignatureCoversWholeDocument(str1);
                    flag1 |= pdfSignatureInfo.SignatureCoversWholeDocument;
                    AcroFields.FieldPosition fieldPosition = acroFields.GetFieldPositions(str1)[0];
                    pdfSignatureInfo.Position = new Rectangle((int)fieldPosition.position.Left, (int)fieldPosition.position.Top, (int)fieldPosition.position.Width, (int)fieldPosition.position.Height);
                    pdfSignatureInfo.PageIndex = fieldPosition.page;
                    using (Stream revision = acroFields.ExtractRevision(str1))
                    {
                        int eofCount = this.GetEOFCount(revision);
                        intList.Add(eofCount);
                    }
                    PdfPKCS7 pdfPkcS7 = acroFields.VerifySignature(str1);
                    pdfSignatureInfo.IsTsp = pdfPkcS7.IsTsp;
                    pdfSignatureInfo.SigningTime = pdfPkcS7.SignDate;
                    DateTime checkingDatetime = pdfSignatureInfo.SigningTime;
                    pdfSignatureInfo.SigningCertificate = pdfPkcS7.SigningCertificate.GetEncoded();
                    TimeStampToken timeStampToken = pdfPkcS7.TimeStampToken;
                    if (timeStampToken != null)
                    {
                        pdfSignatureInfo.TimeStampDate = pdfPkcS7.TimeStampDate.ToLocalTime();
                        checkingDatetime = pdfSignatureInfo.TimeStampDate;
                    }
                    if (!pdfPkcS7.Verify())
                    {
                        s1 = SignatureValidity.DocumentModified;
                        pdfSignatureInfo.ValidityErrors.Add(SignatureValidity.DocumentModified, "Tài liệu đã bị thay đổi.");
                    }
                    else if (!pdfSignatureInfo.SignatureCoversWholeDocument)
                    {
                        s1 = SignatureValidity.NonCoversWholeDocument;
                        pdfSignatureInfo.ValidityErrors.Add(SignatureValidity.NonCoversWholeDocument, "Nội dung đã ký số chưa bị thay đổi. Tuy nhiên, tài liệu đã có những thay đổi trong giới hạn cho phép.");
                    }
                    this.verifyResult |= s1;
                    SignatureValidity signatureValidity = SignatureValidity.None;
                    CertChecker certChecker1 = new CertChecker(new X509Certificate2(pdfSignatureInfo.SigningCertificate), checkingDatetime);
                    certChecker1.AdditionalCRLs = this.additionalCRLs;
                    certChecker1.OnlineCheckingAllowed = this.allowedOnlineChecking;
                    certChecker1.CheckingViaOcsp = false;
                    try
                    {
                        int num = certChecker1.Check();
                        string str2 = "";
                        switch (num)
                        {
                            case 1:
                                signatureValidity = SignatureValidity.InvalidSigningCertificate;
                                str2 = "Chứng thư số đã hết hạn sử dụng";
                                break;
                            case 2:
                                signatureValidity = SignatureValidity.InvalidSigningCertificate;
                                str2 = "Chứng thư số chưa có hiệu lực";
                                break;
                            case 3:
                                signatureValidity = SignatureValidity.InvalidSigningCertificate;
                                str2 = "Đường dẫn chứng thực không hợp lệ";
                                break;
                            case 4:
                                signatureValidity = SignatureValidity.InvalidSigningCertificate;
                                str2 = "Chứng thư số không tin cậy";
                                break;
                            case 5:
                                signatureValidity = SignatureValidity.ErrorCheckingSigningCertificate;
                                str2 = "Lỗi cấu trúc CTS - đường dẫn danh sách CTS bị thu hồi không hợp lệ";
                                break;
                            case 6:
                                signatureValidity = SignatureValidity.ErrorCheckingSigningCertificate;
                                str2 = "Lỗi tải danh sách chứng thư bị thu hồi";
                                break;
                            case 7:
                                signatureValidity = SignatureValidity.NonCheckingRevokedSigningCert;
                                str2 = "Không kiểm tra tình trạng hủy bỏ của chứng thư số ký.";
                                break;
                            case 8:
                                signatureValidity = SignatureValidity.InvalidSigningCertificate;
                                str2 = "Chứng thư số đã bị thu hồi";
                                break;
                            case 9:
                                signatureValidity = SignatureValidity.InvalidSigningCertificate;
                                str2 = "Chứng thư số CA đã bị thu hồi";
                                break;
                            case 10:
                                signatureValidity = SignatureValidity.ErrorCheckingSigningCertificate;
                                str2 = "Danh sách CTS bị thu hồi không hợp lệ";
                                break;
                            case 11:
                                signatureValidity = SignatureValidity.ErrorCheckingSigningCertificate;
                                str2 = "Dịch vụ OCSP trả về kết quả UNKNOWN";
                                break;
                        }
                        if (signatureValidity != SignatureValidity.None)
                            pdfSignatureInfo.ValidityErrors.Add(signatureValidity, str2);
                    }
                    catch (Exception ex)
                    {
                        signatureValidity = SignatureValidity.ErrorCheckingSigningCertificate;
                        pdfSignatureInfo.ValidityErrors.Add(SignatureValidity.ErrorCheckingSigningCertificate, ex.Message);
                    }
                    this.verifyResult |= signatureValidity;
                    SignatureValidity s2 = SignatureValidity.None;
                    try
                    {
                        if (timeStampToken != null)
                        {
                            ICollection signers = timeStampToken.ToCmsSignedData().GetSignerInfos().GetSigners();
                            IX509Store certificates = timeStampToken.GetCertificates("Collection");
                            IEnumerator enumerator = signers.GetEnumerator();
                            try
                            {
                                if (enumerator.MoveNext())
                                {
                                    SignerInformation current = (SignerInformation)enumerator.Current;
                                    Org.BouncyCastle.X509.X509Certificate certificate = PdfVerifier.GetCertificate(current, certificates);
                                    pdfSignatureInfo.TimeStampCertificate = certificate.GetEncoded();
                                    if (!current.Verify(certificate))
                                    {
                                        s2 |= SignatureValidity.InvalidTimestampImprint;
                                        pdfSignatureInfo.ValidityErrors.Add(SignatureValidity.InvalidTimestampImprint, "Dấu thời gian không hợp lệ.");
                                        throw new Exception("Dấu thời gian không hợp lệ.");
                                    }
                                }
                            }
                            finally
                            {
                                if (enumerator is IDisposable disposable)
                                    disposable.Dispose();
                            }
                            if (!pdfPkcS7.IsTsp)
                            {
                                if (!pdfPkcS7.VerifyTimestampImprint())
                                {
                                    s2 = SignatureValidity.InvalidTimestampImprint;
                                    pdfSignatureInfo.ValidityErrors.Add(SignatureValidity.InvalidTimestampImprint, "Dấu thời gian không hợp lệ.");
                                }
                                else
                                {
                                    CertChecker certChecker2 = new CertChecker(new X509Certificate2(pdfSignatureInfo.TimeStampCertificate), checkingDatetime);
                                    certChecker2.AdditionalCRLs = this.additionalCRLs;
                                    certChecker2.OnlineCheckingAllowed = this.allowedOnlineChecking;
                                    certChecker2.CheckingViaOcsp = false;
                                    try
                                    {
                                        int num = certChecker2.Check();
                                        string str3 = "";
                                        SignatureValidity key = SignatureValidity.None;
                                        switch (num)
                                        {
                                            case 1:
                                                key = SignatureValidity.InvalidTSACertificate;
                                                str3 = "Chứng thư số đã hết hạn sử dụng";
                                                break;
                                            case 2:
                                                key = SignatureValidity.InvalidTSACertificate;
                                                str3 = "Chứng thư số chưa có hiệu lực";
                                                break;
                                            case 3:
                                                key = SignatureValidity.InvalidTSACertificate;
                                                str3 = "Đường dẫn chứng thực không hợp lệ";
                                                break;
                                            case 4:
                                                key = SignatureValidity.InvalidTSACertificate;
                                                str3 = "Chứng thư số không tin cậy";
                                                break;
                                            case 5:
                                                key = SignatureValidity.ErrorCheckingTSACertificate;
                                                str3 = "Lỗi cấu trúc CTS - đường dẫn danh sách CTS thu hồi không hợp lệ";
                                                break;
                                            case 6:
                                                key = SignatureValidity.ErrorCheckingTSACertificate;
                                                str3 = "Lỗi tải danh sách chứng thư thu hồi";
                                                break;
                                            case 7:
                                                key = SignatureValidity.NonCheckingRevokedTSACert;
                                                str3 = "Không kiểm tra tình trạng hủy bỏ của chứng thư số máy chủ cấp dấu thời gian.";
                                                break;
                                            case 8:
                                                key = SignatureValidity.InvalidTSACertificate;
                                                str3 = "Chứng thư số đã bị thu hồi";
                                                break;
                                            case 9:
                                                key = SignatureValidity.InvalidTSACertificate;
                                                str3 = "Chứng thư số CA đã thu hồi";
                                                break;
                                            case 10:
                                                key = SignatureValidity.ErrorCheckingTSACertificate;
                                                str3 = "Danh sách CTS thu hồi không hợp lệ";
                                                break;
                                            case 11:
                                                key = SignatureValidity.ErrorCheckingTSACertificate;
                                                str3 = "Dịch vụ OCSP trả về kết quả UNKNOWN";
                                                break;
                                        }
                                        if (key != SignatureValidity.None)
                                        {
                                            pdfSignatureInfo.ValidityErrors.Add(key, str3);
                                            s2 = key;
                                        }
                                    }
                                    catch (Exception ex)
                                    {
                                        s2 = SignatureValidity.ErrorCheckingTSACertificate;
                                        pdfSignatureInfo.ValidityErrors.Add(SignatureValidity.ErrorCheckingTSACertificate, ex.Message);
                                    }
                                }
                            }
                        }
                        else
                        {
                            s2 = SignatureValidity.NotTimestamped;
                            pdfSignatureInfo.ValidityErrors.Add(SignatureValidity.NotTimestamped, "Chữ ký không gắn dấu thời gian.");
                        }
                    }
                    catch (Exception ex)
                    {
                        if (s2 == SignatureValidity.None)
                        {
                            s2 = SignatureValidity.ErrorCheckingTSACertificate;
                            pdfSignatureInfo.ValidityErrors.Add(SignatureValidity.ErrorCheckingTSACertificate, "Lỗi: " + ex.Message);
                        }
                    }
                    this.verifyResult |= s2;
                }
                catch (Exception ex)
                {
                    this.verifyResult |= SignatureValidity.FatalError;
                    pdfSignatureInfo.ValidityErrors.Add(SignatureValidity.FatalError, string.Format("Định dạng chữ ký không hợp lệ ({0})", (object)ex.Message));
                }
                pdfSignatureInfoList.Add(pdfSignatureInfo);
            }
            if (flag1)
            {
                for (int index = intList.Count - 1; index > 0; --index)
                {
                    if (intList[index] - intList[index - 1] > 1)
                    {
                        flag2 = true;
                        break;
                    }
                }
            }
            if (!flag1 | flag2)
            {
                this.verifyResult |= SignatureValidity.DocumentModified;
                foreach (PDFSignatureInfo pdfSignatureInfo in pdfSignatureInfoList)
                    pdfSignatureInfo.ValidityErrors.Add(SignatureValidity.DocumentModified, "Tài liệu đã bị thay đổi.");
            }
        }
        finally
        {
            pdfReader?.Close();
        }
        return pdfSignatureInfoList;
    }
}