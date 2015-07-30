package training.com.trandai.bananasignature;

import java.util.ArrayList;

import SecureBlackbox.Base.TElX509Certificate;
import SecureBlackbox.Office.TElOfficeBinaryXMLSignatureHandler;
import SecureBlackbox.Office.TElOfficeDocument;
import SecureBlackbox.Office.TElOfficeOpenXMLSignatureHandler;
import SecureBlackbox.Office.TElOfficeOpenXPSSignatureHandler;
import SecureBlackbox.Office.TElOpenOfficeSignatureHandler;
import SecureBlackbox.PKI.TElPKCS11CertStorage;
import SecureBlackbox.PKI.TElPKCS11SessionInfo;

/**
 * Created by TranDai on 30/07/2015.
 */
public class Sign_Offices {
    private static TElPKCS11CertStorage Storage;
    private static TElPKCS11SessionInfo session;
    private static ArrayList<TElX509Certificate> listCert;
    private static TElOfficeDocument _OfficeDocument = null;

    public Sign_Offices() {
        Storage = MainSign.Storage;
        session = MainSign.session;
        listCert = MainSign.listCert;
        _OfficeDocument = MainSign._OfficeDocument;
    }

    public boolean signOffices() {
        boolean Success = false;

        try {
            if (_OfficeDocument.getOpenXMLDocument() != null) {
                TElOfficeOpenXMLSignatureHandler OpenXMLSigHandler = new TElOfficeOpenXMLSignatureHandler();
                _OfficeDocument.addSignature(OpenXMLSigHandler, true);

                OpenXMLSigHandler.addDocument();
                OpenXMLSigHandler.getSignatureInfoV1().setIncluded(false);
                OpenXMLSigHandler.sign(listCert.get(MainSign.index));
                System.out.println("SignedOOXML OK");
                Success = true;
            } else if (_OfficeDocument.getOpenXPSDocument() != null) {

                TElOfficeOpenXPSSignatureHandler OpenXPSSigHandler = new TElOfficeOpenXPSSignatureHandler();
                _OfficeDocument.addSignature(OpenXPSSigHandler, true);

                OpenXPSSigHandler.addDocument();
                OpenXPSSigHandler.sign(listCert.get(MainSign.index));
                System.out.println("SignedXPS OK");
                Success = true;
            } else if ((_OfficeDocument.getBinaryDocument() != null)) {
                TElOfficeBinaryXMLSignatureHandler BinXMLSigHandler = new TElOfficeBinaryXMLSignatureHandler();
                _OfficeDocument.addSignature(BinXMLSigHandler, true);

                BinXMLSigHandler.getSignatureInfoV1().setIncluded(false);
                BinXMLSigHandler.sign(listCert.get(MainSign.index));
                System.out.println("SignedBinary OK");
                Success = true;
            } else if ((_OfficeDocument.getOpenDocument() != null)) {
                TElOpenOfficeSignatureHandler ODFSigHandler = new TElOpenOfficeSignatureHandler();
                _OfficeDocument.addSignature(ODFSigHandler, true);

                ODFSigHandler.addDocument();
                ODFSigHandler.sign(listCert.get(MainSign.index));
                System.out.println("SignedODF OK");
                Success = true;
            } else {
                System.out.println("Failed to sign");
                System.exit(1);
                return false;
            }
        } catch (Exception ex) {
            System.out.println("Failed to sign: " + ex.getMessage());
            ex.printStackTrace();
            System.exit(1);
            return false;
        }
        _OfficeDocument.close();
        session.logout();
        Storage.closeAllSessions(Storage.getModule().getSlot(0));
        return Success;
    }
}

