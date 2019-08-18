using System;
using System.Collections.Generic;
using System.IO;
using System.Text.RegularExpressions;
using www.comsigntrust.com;

namespace Tester{
    public class Program{
        private const String certID = "comda";
        private const String pinCode = "123456";
        private const String fnSig = "sig.jpg";
        private const String fnTestPDF = "testPDF.pdf";
        private const String fnSignedPDF = "signedPDF.pdf";
        private const String fnSignedPDFPlaceholder = "signedPDFPlaceholder.pdf";
        private const String fnSignedPDFEncrypted = "signedPDFEncrypted.pdf";
        private const String fnSignedPDFMech = "signedPDFMech.pdf";
        private const String fnTestWord = "testWord.docx";
        private const String fnSignedWord = "signedWord.docx";
        private const String fnTestXml = "testXml.xml";
        private const String fnSignedXml = "signedXml.xml";
        private const String fnSignedXmlForeclosure = "signedXmlFC.xml";
        private const String fnSignedXmlIdNumber = "signedXmlIdNumber.xml";
        private const String fnSignedXmlSigningTime = "signedXmlSigningTime.xml";
        private const String fnTestTiff = "testTiff.tiff";
        private const String fnSignedTiff = "signedTiff.tiff";
        private const String fnTestExcel = "testExcel.xlsx";
        private const String fnSignedExcel = "signedExcel.xlsx";
        private const String fnPosted = "imagePosted.pdf";
        //private const String token = "8b0297c2-16cc-0cc2-2ca8-6f5699586b0e";
        private const String idNumber = "12345678";
        private const String date = "08-18-2019";
        private static readonly byte[] digest = { 1, 2, 3, 4 };
        private static byte[] dygestedContent;
        private static readonly String[] tests = { "GetVersion", "SignPDF_PIN", "VerifyPDF", "SignPDF_PIN_Placeholder", "SignWord_PIN", "SignExcel_PIN", "SignXml_PIN", "SignTiff_PIN", "VerifyTiff", "SignPDF_PIN_FilePath", "SignPDF_SetImage", "Get_PDFSigners", "SignForeclosure", "EncryptPDF_UserOwnerPasswords", "SignCMS_PIN", "VerifyCMS", "SignRAW_PIN", "SignMeches_PIN", "AddIdNumberToIkul", "AddSigningTime", "Cred_IsAvailable", "Cred_Verify", "GetCardInfo", "SetCred_Absolute", "SetCred_Sliding", "SignPDF_NOPIN", "SignPDF_NOPIN_FIELD", "SignCMS_NOPIN", "SignWord_NOPIN", "SignExcel_NOPIN", "SignTiff_NOPIN", "Cred_Remove" };
        private static SignServiceClient client = null;
        private static StreamWriter writetext = null;
        public static void Main(string[] args){
            client = new SignServiceClient();
            writetext = new StreamWriter("log.txt");
            writeToFile("Application started");

            foreach (String test in tests)
                performTest(test);

            writeToFile("\nApplication ended, all logs recorded in log.txt");
            writetext.Close();
            client.Close();
            String filePath = Console.ReadLine();
        }
        public static void performTest(String method) {
            bool print = true;
            ResCode res_code = new ResCode();
            SignResponse resp = null;
            writeToFile("\nTESTING: "+ method);
            switch (method) {
                case string t when t == "SignPDF_NOPIN":
                    resp = client.SignPDF_NOPIN(certID, File.ReadAllBytes(fnTestPDF), 1, 0, 0, 150, 150, File.ReadAllBytes(fnSig), "");
                    res_code = resp.Result;
                    if (resp.SignedBytes != null) 
                        saveFile(fnSignedPDF, resp.SignedBytes);
                    break;
                case string t when t == "SignPDF_NOPIN_FIELD":
                    print = false;
                    writeToFile("* " + method + " method was not defined");
                    break;
                case string t when t == "SignPDF_PIN_FilePath":
                    print = false;
                    //String path = Path.GetFullPath(fnTest);
                    //String path = fnTest;
                    //String path = "/etc/hosts";
                    //String path = "C:\\Windows\\System32\\cmd.exe";
                    String path = "C:\\inetpub\\wwwroot\\iisstart.htm";
                    //String path = "signed.pdf";
                    //String path = "C:\\test.pdf";
                    res_code = client.SignPDF_PIN_FilePath(certID,path,"aaa.pdf",1,0, 0, 150, 150,pinCode,File.ReadAllBytes(fnSig),"").Result;
                    writeToFile("Not testing 'SignPDF_PIN_FilePath' functionality as it takes input file paths that are located on the server side.");
                    break;
                case string t when t == "SignPDF_PIN":
                    resp = client.SignPDF_PIN(certID,File.ReadAllBytes(fnTestPDF),1,0, 0, 150, 150,pinCode,File.ReadAllBytes(fnSig),"");
                    res_code = resp.Result;
                    if (resp.SignedBytes != null) 
                        saveFile(fnSignedPDF, resp.SignedBytes);
                    break;
                case string t when t == "SignPDF_SetImage":
                    resp = client.SignPDF_SetImage(File.ReadAllBytes(fnTestPDF),1,0, 0, 150, 150,File.ReadAllBytes(fnSig),"");
                    res_code = resp.Result;
                    if (resp.SignedBytes != null) 
                        saveFile(fnPosted, resp.SignedBytes);
                    break;
                case string t when t == "Get_PDFSigners":
                    print = false;
                    String[] strRes = client.Get_PDFSigners(File.ReadAllBytes(fnSignedPDF), "");
                    writeToFile("Exspected strRes is: " + "NOT NULL");
                    writeToFile("strRes is: " + String.Join("", strRes));
                    writeToFile("TEST " + (strRes != null ? "PASSED" : "FAILED"));
                    break;
                case string t when t == "VerifyPDF":
                    MultiSignValidationResponse msvRes= client.VerifyPDF(File.ReadAllBytes(fnSignedPDF));
                    res_code = msvRes.OperationResult;
                    break;
                case string t when t == "SignPDF_PIN_Placeholder":
                    resp = client.SignPDF_PIN_Placeholder(certID, File.ReadAllBytes(fnTestPDF), pinCode, "dip", 150, 150, File.ReadAllBytes(fnSig), "");
                    res_code = resp.Result;
                    if (resp.SignedBytes != null)
                        saveFile(fnSignedPDFPlaceholder, resp.SignedBytes);
                    break;
                case string t when t == "EncryptPDF_UserOwnerPasswords":
                    resp = client.EncryptPDF_UserOwnerPasswords(File.ReadAllBytes(fnTestPDF),"tony1","tony");
                    res_code = resp.Result;
                    if (resp.SignedBytes != null)
                        saveFile(fnSignedPDFEncrypted, resp.SignedBytes);
                    break;
                case string t when t == "SignCMS_PIN":
                    resp = client.SignCMS_PIN(certID, digest, pinCode, CTInterfaces.CTDigestAlg.SHA1, "","");
                    if (resp.SignedBytes != null) 
                        dygestedContent = resp.SignedBytes;
                    res_code = resp.Result;
                    break;
                case string t when t == "SignCMS_NOPIN":
                    print = false;
                    writeToFile("* " + method + " method was not defined");
                    break;
                case string t when t == "SignRAW_PIN":
                    resp = client.SignRAW_PIN(certID, CTInterfaces.CTDigestAlg.SHA1, digest, pinCode, "");
                    res_code = resp.Result;
                    break;
                case string t when t == "VerifyCMS":
                    if(dygestedContent != null) {
                        resp = client.VerifyCMS(digest, dygestedContent);
                        res_code = resp.Result;
                    }
                    else
                        res_code = ResCode.NO_PERM_TOKEN_PROVIDED;
                    break;
                case string t when t == "SignXml_PIN":
                    resp = client.SignXml_PIN(certID, File.ReadAllBytes(fnTestXml), pinCode, "");
                    res_code = resp.Result;
                    if (resp.SignedBytes != null)
                        saveFile(fnSignedXml, resp.SignedBytes);
                    else
                        writeToFile("Error: " + res_code);
                    break;
                case string t when t == "SignForeclosure":
                    resp = client.SignForeclosure(certID, pinCode, File.ReadAllBytes(fnTestXml), "");
                    res_code = resp.Result;
                    if (resp.SignedBytes != null)
                        saveFile(fnSignedXmlForeclosure, resp.SignedBytes);
                    break;
                case string t when t == "AddIdNumberToIkul":
                    resp = client.AddIdNumberToIkul(File.ReadAllBytes(fnTestXml), idNumber, "");
                    res_code = resp.Result;
                    if (resp.SignedBytes != null)
                        saveFile(fnSignedXmlIdNumber, resp.SignedBytes);
                    break;
                case string t when t == "AddSigningTime":
                    resp = client.AddSigningTime(File.ReadAllBytes(fnTestXml), date, "");
                    res_code = resp.Result;
                    if (resp.SignedBytes != null)
                        saveFile(fnSignedXmlSigningTime, resp.SignedBytes);
                    break;
                case string t when t == "SetCred_Absolute":
                    try {
                        res_code = client.SetCred_Absolute(certID, pinCode, new DateTime(2050,1,1), "", "");
                    }
                    catch (Exception e) {
                        print = false;
                        writeToFile("EXCEPRION: "+e.ToString());
                    }
                    break;
                case string t when t == "SetCred_Sliding":
                    try {
                        res_code = client.SetCred_Sliding(certID, pinCode, new TimeSpan(13, 0, 0), "", "");
                    }catch (Exception e) {
                        print = false;
                        writeToFile("EXCEPRION: " + e.ToString());
                    }
                    break;
                case string t when t == "Cred_Verify":
                    res_code = client.Cred_Verify(certID, pinCode, "");
                    break;
                case string t when t == "Cred_IsAvailable":
                    print = false;
                    bool boolRes = client.Cred_IsAvailable(certID, "", "");
                    writeToFile("Exspected Result is: " + true);
                    writeToFile("Result is: " + boolRes.ToString());
                    writeToFile("TEST " + (boolRes == true ? "PASSED" : "FAILED"));
                    break;
                case string t when t == "Cred_Remove":

                    print = false;
                    writeToFile("* " + method + " method was not defined");
                    break;
                case string t when t == "GetVersion":
                    String version = client.GetVersion().ToString();
                    if (IsValidVersion(version)) {
                        res_code = ResCode.SUCCESS;
                        writeToFile("Version is: " + client.GetVersion().ToString());
                    }
                    else
                        res_code = ResCode.NO_PERM_TOKEN_PROVIDED;
                    break;
                case string t when t == "GetCardInfo":
                    CardInfoResponse info = client.GetCardInfo(certID, pinCode, "");
                    res_code = info.Result;
                    break;
                case string t when t == "SignWord_PIN":
                    resp = client.SignWord_PIN(certID, File.ReadAllBytes(fnTestWord), pinCode,"","");
                    res_code = resp.Result;
                    if (resp.SignedBytes != null)
                        saveFile(fnSignedWord, resp.SignedBytes);
                    break;
                case string t when t == "SignExcel_PIN":
                    resp = client.SignExcel_PIN(certID, File.ReadAllBytes(fnTestExcel), pinCode, "", "");
                    res_code = resp.Result;
                    if (resp.SignedBytes != null)
                        saveFile(fnSignedExcel, resp.SignedBytes);
                    break;
                case string t when t == "SignTiff_PIN":
                    resp = client.SignTiff_PIN(certID, File.ReadAllBytes(fnTestTiff), pinCode,150,150, File.ReadAllBytes(fnSig), "", "");
                    res_code = resp.Result;
                    if (resp.SignedBytes != null)
                        saveFile(fnSignedTiff, resp.SignedBytes);
                    break;
                case string t when t == "VerifyTiff":
                    MultiSignValidationResponse msvResTiff = client.VerifyTiff(File.ReadAllBytes(fnSignedTiff));
                    res_code = msvResTiff.OperationResult;
                    break;
                case string t when t == "SignWord_NOPIN":
                    print = false;
                    writeToFile("* " + method + " method was not defined");
                    break;
                case string t when t == "SignExcel_NOPIN":
                    print = false;
                    writeToFile("* " + method + " method was not defined");
                    break;
                case string t when t == "SignTiff_NOPIN":
                    print = false;
                    writeToFile("* " + method + " method was not defined");
                    break;
                case string t when t == "SignMeches_PIN":
                    resp = client.SignMeches_PIN(certID, File.ReadAllBytes(fnTestPDF),"","pdf", pinCode, "");
                    res_code = resp.Result;
                    if (resp.SignedBytes != null)
                        saveFile(fnSignedPDFMech, resp.SignedBytes);
                    break;
            }

            if(print) {
                writeToFile("Exspected ResCode is: " + ResCode.SUCCESS.ToString());
                writeToFile("ResCode is: " + res_code.ToString());
                writeToFile("TEST " + (res_code == ResCode.SUCCESS ? "PASSED" : "FAILED"));
            }
        }
        public static void writeToFile(String line){
            System.Console.WriteLine(line);
            writetext.Write(line+"\n");
        }
        public static void saveFile(String path, byte[] bytes) {
            writeToFile("Saving file...");
            File.WriteAllBytes(path, bytes);
            writeToFile("File saved -> " + path);
        }
        private static bool IsValidVersion(string ver) {
            try {
                Regex.Match(ver, "\\d+\\.\\d+\\.\\d+\\.\\d+");
            }
            catch (ArgumentException) {
                return false;
            }
            return true;
        }
    }
}
