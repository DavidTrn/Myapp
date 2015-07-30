package training.com.trandai.bananasignature;

import android.util.Log;

import org.freepascal.rtl.TObject;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.security.cert.CertificateException;
import java.util.ArrayList;

import SecureBlackbox.Base.SBUtils;
import SecureBlackbox.Base.TElFileStream;
import SecureBlackbox.Base.TElMemoryCertStorage;
import SecureBlackbox.Base.TElX509Certificate;
import SecureBlackbox.PDF.TElPDFDocument;
import SecureBlackbox.PDF.TElPDFPublicKeySecurityHandler;
import SecureBlackbox.PDF.TElPDFSignature;
import SecureBlackbox.PDF.TElPDFSignatureWidgetProps;
import SecureBlackbox.PDF.TSBPDFConvertStringToAnsiEvent;
import SecureBlackbox.PDF.TSBPDFLookupGlyphNameEvent;
import SecureBlackbox.PDF.TSBPDFPublicKeySignatureType;
import SecureBlackbox.PKI.TElPKCS11CertStorage;

/**
 * Created by TranDai on 30/07/2015.
 */
public class Sign_PDF {
    private static TElPKCS11CertStorage Storage;
    private static TElPDFDocument Document;
    private static TElMemoryCertStorage CertStorage;
    private static TElPDFPublicKeySecurityHandler PublicKeyHandler;
    private static ArrayList<TElX509Certificate> listCert;
    private String[] _GlyphNames;


    public  Sign_PDF() {
        Storage = MainSign.Storage;
        Document = MainSign.Document;
        CertStorage = MainSign.CertStorage;
        PublicKeyHandler = MainSign.PublicKeyHandler;
        listCert = MainSign.listCert;
        _GlyphNames = MainSign._GlyphNames;
    }

    public boolean signPDF(String des_path) throws IOException, CertificateException {

        boolean Success = false;
        //String TempPath = getTempFileName();

        try {
            // opening the temporary file
            TElFileStream F = new TElFileStream(des_path, "rw", true);

            try
            {
                Document.open(F);
                // checking if the document is already encrypted
                if (Document.getEncrypted())
                {
                    Success = false;
                    return Success;
                }

                AddSignature(Document, listCert.get(MainSign.index));

                Success = true;
            } catch(Exception ex){
                ex.printStackTrace();
                Success = false;
            } finally{
                Document.close(Success);
                F.Free();
            }
        } catch(Exception e) {
            e.printStackTrace();
            Success = false;
        }

        return Success;

    }

    public void AddSignature(TElPDFDocument Document, TElX509Certificate FCert) throws Exception
    {

        if (FCert == null)
            throw new Exception("Failed to load encryption certificate");

        // adding the signature and setting up property values
        int index = Document.addSignature();
        TElPDFSignature Sig = Document.getSignatureEntry(index);

        TElPDFSignatureWidgetProps widgetPro = Sig.getWidgetProps();
        widgetPro.setAutoSize(false);
        widgetPro.setAutoPos(false);
        widgetPro.setAutoFontSize(true);
        widgetPro.setOffsetX(200);
        widgetPro.setOffsetY(30);
        widgetPro.setWidth(180);
        widgetPro.setHeight(70);


        Sig.setAuthorName("daitran");
        Sig.setSigningTime(SBUtils.utcNow());
        Sig.setReason("I like it");
        Sig.setInvisible(true);
        // adding certificate to certificate storage
        CertStorage.clear();
        PublicKeyHandler.setSignatureType(TSBPDFPublicKeySignatureType.pstPKCS7SHA1);
        CertStorage.add(FCert, true);
        PublicKeyHandler.setCertStorage(CertStorage);
        PublicKeyHandler.setCustomName("Adobe.PPKMS");

        // configuring time stamping settings
        Sig.setHandler(PublicKeyHandler);
    }

    TSBPDFConvertStringToAnsiEvent.Callback UTF16ToWin1252 = new TSBPDFConvertStringToAnsiEvent.Callback() {

        public byte[] tsbpdfConvertStringToAnsiEventCallback(TObject sender,
                                                             String s) {
            return s.getBytes();
        }
    };

    TSBPDFLookupGlyphNameEvent.Callback LookupGlyphName = new TSBPDFLookupGlyphNameEvent.Callback() {

        public String tsbpdfLookupGlyphNameEventCallback(TObject sender, int ucs) {
            return LookupGlyphName(sender, ucs);
        }
    };

    private String LookupGlyphName(Object sender, int UCS)
    {
        // Full list: http://partners.adobe.com/public/developer/en/opentype/glyphlist.txt

        if (_GlyphNames == null)
        {
            _GlyphNames = new String[0x10000];
            String Data = getURLData("http://partners.adobe.com/public/developer/en/opentype/glyphlist.txt");

            String[] Lines = Data.split("\n" );
            for (int i = 0; i < Lines.length; i++)
                if ((Lines[i].length() > 0) && (Lines[i].charAt(0) != '#'))
                {
                    String[] ss = Lines[i].split(";");
                    if (ss.length != 2)
                        continue;

                    String GlyphName = ss[0]; // glyph name
                    ss = ss[1].split(""); // codes
                    if (ss.length != 1)
                        continue; // skipping surrogate pairs

                    int code = (int)Integer.parseInt(ss[0]);
                    _GlyphNames[code] = GlyphName;
                }
        }

        if (UCS < _GlyphNames.length)
            return _GlyphNames[UCS];
        else
            return "";
    }

    private String getURLData(String url) {
        String result = "";

        try {

            URL u = new URL(url);

            InputStream is = u.openStream();

            BufferedReader sr = new BufferedReader(new InputStreamReader(is));

            String s = "";
            while ((s = sr.readLine()) != null) {
                result += s;
            }

            sr.close();
            is.close();

        } catch (Exception e) {
            e.printStackTrace();
        }

        return result;
    }

}
