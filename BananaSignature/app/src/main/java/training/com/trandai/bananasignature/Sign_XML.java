package training.com.trandai.bananasignature;

import android.util.Log;

import org.freepascal.rtl.TObject;

import java.util.ArrayList;
import java.util.Date;

import SecureBlackbox.Base.SBConstants;
import SecureBlackbox.Base.SBRandom;
import SecureBlackbox.Base.SBStrUtils;
import SecureBlackbox.Base.TElFileStream;
import SecureBlackbox.Base.TElMemoryCertStorage;
import SecureBlackbox.Base.TElX509Certificate;
import SecureBlackbox.Base.TSBObject;
import SecureBlackbox.HTTPClient.TElHTTPSClient;
import SecureBlackbox.HTTPClient.TElHTTPTSPClient;
import SecureBlackbox.PKI.TElPKCS11CertStorage;
import SecureBlackbox.XML.SBXMLCore;
import SecureBlackbox.XML.SBXMLDefs;
import SecureBlackbox.XML.TElXMLDOMDocument;
import SecureBlackbox.XML.TElXMLDOMElement;
import SecureBlackbox.XML.TElXMLDOMNode;
import SecureBlackbox.XMLSecurity.SBXMLAdES;
import SecureBlackbox.XMLSecurity.SBXMLAdESIntf;
import SecureBlackbox.XMLSecurity.SBXMLSec;
import SecureBlackbox.XMLSecurity.TElXAdESSigner;
import SecureBlackbox.XMLSecurity.TElXMLEnvelopedSignatureTransform;
import SecureBlackbox.XMLSecurity.TElXMLFormatElementParams;
import SecureBlackbox.XMLSecurity.TElXMLKeyInfoPGPData;
import SecureBlackbox.XMLSecurity.TElXMLKeyInfoX509Data;
import SecureBlackbox.XMLSecurity.TElXMLReference;
import SecureBlackbox.XMLSecurity.TElXMLReferenceList;
import SecureBlackbox.XMLSecurity.TElXMLSigner;
import SecureBlackbox.XMLSecurity.TSBXMLFormatElementEvent;
import SecureBlackbox.XMLSecurity.TSBXMLFormatTextEvent;

/**
 * Created by TranDai on 30/07/2015.
 */
public class Sign_XML {
    private static TElPKCS11CertStorage Storage;
    private static ArrayList<TElX509Certificate> listCert;

    private static TElXMLDOMDocument FXMLDocument = null;

    private static short[] SIGNATURE_TYPE = {
            SBXMLSec.xstEnveloping,
            SBXMLSec.xstDetached,
            SBXMLSec.xstEnveloped
    };
    private static short[] CANONICOLIZATION_METHOD = {
            SBXMLDefs.xcmCanon,
            SBXMLDefs.xcmCanonComment,
            SBXMLDefs.xcmMinCanon
    };
    private static short[] SIGNATURE_METHOD_TYPE = {
            SBXMLSec.xmtSig
    };
    private static short[] SIGNATURE_METHOD = {
            SBXMLSec.xsmDSS,
            SBXMLSec.xsmRSA_SHA1,
            SBXMLSec.xsmRSA_MD5,
            SBXMLSec.xsmRSA_SHA256,
            SBXMLSec.xsmRSA_SHA384,
            SBXMLSec.xsmRSA_SHA512,
            SBXMLSec.xsmRSA_RIPEMD160
    };
    private static short[] HMAC_METHOD = {
            SBXMLSec.xmmHMAC_MD5,
            SBXMLSec.xmmHMAC_SHA1,
            SBXMLSec.xmmHMAC_SHA224,
            SBXMLSec.xmmHMAC_SHA256,
            SBXMLSec.xmmHMAC_SHA384,
            SBXMLSec.xmmHMAC_SHA512,
            SBXMLSec.xmmHMAC_RIPEMD160
    };

    private static short[] XADES_VERSION = {
            SBXMLAdES.XAdES_v1_1_1,
            SBXMLAdES.XAdES_v1_2_2,
            SBXMLAdES.XAdES_v1_3_2
    };

    public Sign_XML() {
        Storage = MainSign.Storage;
        listCert = MainSign.listCert;
    }

    public boolean signXML() {
        boolean Success = false;

        TElXMLSigner Signer;
        TElXAdESSigner XAdESSigner = null;
        TElXMLKeyInfoX509Data X509KeyData = null;
        TElXMLKeyInfoPGPData PGPKeyData = null;
        TElFileStream F;
        TElXMLDOMNode SigNode;
        TElXMLReference Ref = null;
        TElXMLReferenceList Refs = new TElXMLReferenceList();
        TElHTTPSClient HTTPClient = null;
        TElHTTPTSPClient TSPClient = null;

        TElMemoryCertStorage FCertStorage = new TElMemoryCertStorage();


        FXMLDocument = new TElXMLDOMDocument();
        try
        {
            F = new TElFileStream(MainSign.src_path, "rw", true);
            FXMLDocument.loadFromStream(F);
        }
        catch (Exception e)
        {
            e.printStackTrace();
            System.exit(1);
            return false;
        }

        if (F != null)
            F.Free();

        Ref = new TElXMLReference();
        Ref.setDigestMethod(SBXMLSec.xdmSHA1);

        if (FXMLDocument instanceof TElXMLDOMDocument)
        {
            Ref.setURI("");
            Ref.setURINode(FXMLDocument.getDocumentElement());
        }

        Ref.getTransformChain().add(new TElXMLEnvelopedSignatureTransform());
        Refs.add(Ref);

        Signer = new TElXMLSigner();
        try
        {
            Signer.setSignatureType(SIGNATURE_TYPE[2]);
            Signer.setCanonicalizationMethod(CANONICOLIZATION_METHOD[0]);
            Signer.setSignatureMethodType(SIGNATURE_METHOD_TYPE[0]);
            Signer.setSignatureMethod(SIGNATURE_METHOD[1]);
            Signer.setMACMethod(HMAC_METHOD[1]);
            Signer.setReferences(Refs);
            Signer.setKeyName("MTCS-XML Mobile Signer");
            Signer.setIncludeKey(true);

            Signer.setOnFormatElement(new TSBXMLFormatElementEvent(formatElementClb));
            Signer.setOnFormatText(new TSBXMLFormatTextEvent(formatTextClb));

            Log.e(MainSign.TAG, MainSign.index + "..");
            TElX509Certificate Cert = listCert.get(MainSign.index);

            FCertStorage.add(Cert, true);

            if ((Signer.getSignatureType() == SBXMLSec.xstEnveloping) && (Ref != null) && (Ref.getURI().compareTo("") == 0) && (Ref.getURINode() instanceof TElXMLDOMElement))
            {
                TElXMLDOMElement El = (TElXMLDOMElement)Ref.getURINode();
                El.setAttribute("Id", "id-" + SBStrUtils.intToStr(SBRandom.sbRndGenerate(Integer.MAX_VALUE)));
                Ref.setURI("#" + El.getAttribute("Id"));
            }

            if ((Cert != null) && Cert.getPrivateKeyExists())
            {
                X509KeyData = new TElXMLKeyInfoX509Data(false);
                X509KeyData.setCertificate(Cert);
                Signer.setKeyData(X509KeyData);
            }
            boolean isXAdES = true;
            if (isXAdES)
            {
                XAdESSigner = new TElXAdESSigner();
                Signer.setXAdESProcessor(XAdESSigner);
                XAdESSigner.setXAdESVersion(XADES_VERSION[2]);

                XAdESSigner.getPolicyId().getSigPolicyId().setDescription("CAG360 XAdES Description");
                XAdESSigner.getPolicyId().getSigPolicyId().getDocumentationReferences().add("CAG360 XAdES Documentation references");
                String s = "CAG360 XAdES Identifier";
                XAdESSigner.getPolicyId().getSigPolicyId().setIdentifier(s);
                if (s.length() > 0)
                {
                    if (s.toLowerCase().startsWith("urn:"))
                        XAdESSigner.getPolicyId().getSigPolicyId().setIdentifierQualifier(SBXMLAdES.xqtOIDAsURN);
                    else
                        XAdESSigner.getPolicyId().getSigPolicyId().setIdentifierQualifier(SBXMLAdES.xqtOIDAsURI);
                }
                else
                    XAdESSigner.getPolicyId().getSigPolicyId().setIdentifierQualifier(SBXMLAdES.xqtNone);
                boolean isProductionPlace = true;
                if (isProductionPlace)
                {
                    XAdESSigner.setIncluded(SBXMLAdESIntf.xipProductionPlace);
                    XAdESSigner.getProductionPlace().setCity("Ho Chi Minh");
                    XAdESSigner.getProductionPlace().setStateOrProvince("Q1");
                    XAdESSigner.getProductionPlace().setPostalCode("7000");
                    XAdESSigner.getProductionPlace().setCountryName("Vietnam");
                }
                boolean isTimeStamp = false;
                String timestamp_url = "http://192.168.1.241/CAG360/process?workerId=32";
                if (isTimeStamp)
                {
                    TSPClient = new TElHTTPTSPClient();
                    HTTPClient = new TElHTTPSClient();
                    TSPClient.setHTTPClient(HTTPClient);
                    TSPClient.setURL(timestamp_url);

                    TSPClient.setHashAlgorithm(SBConstants.SB_ALGORITHM_DGST_SHA1);
                    XAdESSigner.setTSPClient(TSPClient);
                    XAdESSigner.setIgnoreTimestampFailure(false);
                }

                XAdESSigner.setSigningCertificates(FCertStorage);

                XAdESSigner.setSigningTime(new Date());

                // create XAdESSigner.QualifyingProperties
                XAdESSigner.generate();

                // Finally we can modify QualifyingProperties if needed
                // For example set xades prefix:
                XAdESSigner.getQualifyingProperties().setXAdESPrefix("xades");
            }

            Signer.updateReferencesDigest();

            if (Signer.getSignatureType() == SBXMLSec.xstDetached)
            {
                Signer.generateSignature();

                FXMLDocument.Destroy();
                try
                {
                    SigNode = null;
                    TSBObject obj = new TSBObject();
                    Signer.save(obj);
                    SigNode = (TElXMLDOMNode)obj.value;
                    FXMLDocument = SigNode.getOwnerDocument();
                }
                catch (Exception E)
                {
                    FXMLDocument = new TElXMLDOMDocument();
                    System.out.println("Signed data saving failed. " + E.getMessage());
                    E.printStackTrace();
                    System.exit(1);
                    return false;
                }
            }
            else
            {
                if (FXMLDocument == null)
                {
                    System.out.println("Please, select node for signing.");
                    System.exit(1);
                    return false;
                }

                Signer.generateSignature();

                SigNode = (TElXMLDOMNode)FXMLDocument;
                if (SigNode instanceof TElXMLDOMDocument) {
                    TElXMLDOMElement ckdt = ((TElXMLDOMDocument)SigNode).createElement("CKyDTu");
                    ((TElXMLDOMDocument)SigNode).getDocumentElement().appendChild(ckdt);
                    SigNode = ckdt;
                    //SigNode = ((TElXMLDOMDocument)SigNode).getDocumentElement();
                }

                try
                {
                    // If the signature type is enveloping, then the signature is placed into the passed node and the contents of the node are moved to inside of the signature.
                    // If the signature type is enveloped, the signature is placed as a child of the passed node.
                    TSBObject obj = new TSBObject();
                    obj.value = SigNode;
                    //System.out.println(SigNode.getLocalName());
                    Signer.save(obj);
                }
                catch (Exception E)
                {
                    E.printStackTrace();
                    System.out.println("Signed data saving failed. " + E.getMessage());
                    System.exit(1);
                    return false;
                }
            }
            //updateXML();

            TElFileStream F1 = null;
            try
            {
                F1 = new TElFileStream(MainSign.des_path, "rw", true);
                FXMLDocument.saveToStream(F1, SBXMLDefs.xcmNone, "");
            }
            catch (Exception ex)
            {
                ex.printStackTrace();
                System.exit(1);
                return false;
            }
            if (F1 != null)
                F1.Free();
            Success = true;

        }
        catch(Exception E) {
            E.printStackTrace();
            Success = false;
        }
        finally
        {
            Signer.Destroy();
            if (XAdESSigner != null)
                XAdESSigner.Destroy();
            if (TSPClient != null)
                TSPClient.Destroy();
            if (X509KeyData != null)
                X509KeyData.Destroy();
            if (PGPKeyData != null)
                PGPKeyData.Destroy();
            //Success = true;
        }

        return Success;
    }

    static TSBXMLFormatElementEvent.Callback formatElementClb = new TSBXMLFormatElementEvent.Callback() {
        public void tsbxmlFormatElementEventCallback(TObject sender, TElXMLDOMElement elem, int level, String path, TElXMLFormatElementParams params) {
            params.StartTagWhitespace = "\n";
            char tab[] = {'\t'};
            String s = new String(tab);

            params.StartTagWhitespace = params.StartTagWhitespace + s;
            if (elem.getFirstChild() != null)
            {
                boolean HasElements = false;
                TElXMLDOMNode Node = elem.getFirstChild();
                while (Node != null)
                {
                    if (Node.getNodeType() == SBXMLCore.ntElement)
                    {
                        HasElements = true;
                        break;
                    }

                    Node = Node.getNextSibling();
                }

                if (HasElements)
                    params.EndTagWhitespace = "\n" + s;
            }
        }
    };

    static TSBXMLFormatTextEvent.Callback formatTextClb = new TSBXMLFormatTextEvent.Callback() {

        public String tsbxmlFormatTextEventCallback(TObject sendet, String text,
                                                    short textType, int level, String path) {
            if ((textType == SBXMLDefs.ttBase64) && (text.length() > 64))
            {
                String s = "\n";
                while (text.length() > 0)
                {
                    if (text.length() > 64)
                    {
                        s = s + text.substring(0, 64) + "\n";
                        text = text.substring(64);
                    }
                    else
                    {
                        s = s + text + "\n";
                        text = "";
                    }
                }

                text = s + createString('\t', level - 2);
            }

            return text;
        }
    };

    private static String createString(char n, int len) {
        StringBuilder sb = new StringBuilder(len);
        while (len-- > 0)
            sb.append(n);

        return sb.toString();
    }
}

