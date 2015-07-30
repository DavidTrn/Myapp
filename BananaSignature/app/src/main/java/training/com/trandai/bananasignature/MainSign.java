package training.com.trandai.bananasignature;

import android.app.ActivityGroup;
import android.app.AlertDialog;
import android.app.Dialog;
import android.app.ProgressDialog;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.res.Resources;
import android.database.Cursor;
import android.net.Uri;
import android.os.Environment;
import android.os.Handler;
import android.os.Message;
import android.os.Bundle;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewGroup;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ImageButton;
import android.widget.LinearLayout;
import android.widget.ListView;
import android.widget.TextView;
import android.widget.Toast;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URISyntaxException;
import java.security.cert.CertificateException;
import java.util.ArrayList;

import SecureBlackbox.Base.JNI;
import SecureBlackbox.Base.SBUtils;
import SecureBlackbox.Base.TElMemoryCertStorage;
import SecureBlackbox.Base.TElX509Certificate;
import SecureBlackbox.Office.TElOfficeDocument;
import SecureBlackbox.PDF.SBPDF;
import SecureBlackbox.PDF.SBPDFSecurity;
import SecureBlackbox.PDF.TElPDFDocument;
import SecureBlackbox.PDF.TElPDFPublicKeySecurityHandler;
import SecureBlackbox.PKI.SBPKCS11Base;
import SecureBlackbox.PKI.TElPKCS11CertStorage;
import SecureBlackbox.PKI.TElPKCS11SessionInfo;
import cfca.mobile.keydevice.AudioToken;
import feitian.key.audio.sdk.AudioKeyExcep;


public class MainSign extends ActivityGroup {
    LinearLayout viewLogin, viewSign, viewChooseFileType;
    String [] tmp = null;
    String s = "";

    EditText edtLogin;
    ImageButton ibLogout, ib_back;

    static ArrayList<TElX509Certificate> listCert = new ArrayList<>();

    Button btnBrowseSrc, btnBrowseDes, btnSign, btnSignPDF, btnSignOffices, btnSignXML, btnLogin;
    EditText edtSrc, edtDes, edtNameFileSign, edtCert;

    public static final String TAG = "MyDebug";
    FileDialog fileDialog = null;

    Resources res;
    static Context context;
    private ProgressDialog progressDialog;
    private BroadcastReceiver headSetReceiver = null;
    private handler handler;
    private Dialog dialog;
    public static int index;

    public static String src_path = null;
    public static String des_path = null;

    public static TElPKCS11CertStorage Storage;
    public static TElPKCS11SessionInfo session;
    public static TElPDFDocument Document;
    public static TElMemoryCertStorage CertStorage;
    public static TElPDFPublicKeySecurityHandler PublicKeyHandler;
    public static String[] _GlyphNames;

    public static TElOfficeDocument _OfficeDocument = null;

    public Sign_PDF signPDF = null;
    public Sign_Offices signOffice = null;
    public Sign_XML signXML = null;

    public static final int SHOWPROGRESSDIALOG 		= 0x00000010;
    public static final int CLOSEPROGRESSDIALOG 	= 0x00000011;
    public static final int LOGINSUCCESS			= 0x00000012;
    public static final int VERIFYPASSWORD			= 0x00000100;
    public static final int SHOWINFO			    = 0x00000102;
    public static final int SIGNIN			        = 0x00000103;
    public static final int DOSIGN			        = 0x00000104;
    public static final int SHOWDIALOG			    = 0x00000105;


    public  static boolean isLogin = false;

    public static boolean PDF_flag = false;
    public static boolean Office_flag = false;
    public static boolean XML_flag = false;
    private boolean isConnected = false;

    public class handler extends Handler {
        public void sleep(long delayMillis, int msgID, Object obj) {
            this.removeMessages(msgID);
            Message msg = new Message();
            msg.what = msgID;
            msg.obj  = obj;
            sendMessageDelayed(msg, delayMillis);
        }

        public void handleMessage(Message msg) {
            switch(msg.what) {

                case SHOWINFO:
                    if (null != msg.obj)
                        showMessage(msg.obj.toString());
                    super.handleMessage(msg);
                    break;

                case SHOWPROGRESSDIALOG:
                    Log.e(TAG, "SHOWPROGRESSDIALOG");
                    progressDialog.show();
                    super.handleMessage(msg);
                    break;

                case CLOSEPROGRESSDIALOG:
                    progressDialog.dismiss();
                    super.handleMessage(msg);
                    break;

                case LOGINSUCCESS:
                    isLogin = true;
                    changeView();
                    Log.e(TAG, "LOGINSUCCESS");
                    break;

                case VERIFYPASSWORD:
                    Log.e(TAG, "VERIFYPASSWORD");
                    myLogin(msg.obj.toString());
                    Log.e(TAG, "VERIFYPASSWORD...");
                    super.handleMessage(msg);
                    break;

                case SHOWDIALOG:
                    showDialog(3);
                    super.handleMessage(msg);
                    break;

                case SIGNIN:
                    copyFileUsingFileStreams(src_path, des_path);
                    if (PDF_flag) {
                        signPDF = new Sign_PDF();
                        showDialog(3);
                        try {
                            signPDF.signPDF(des_path);
                        } catch (IOException e) {
                            e.printStackTrace();
                        } catch (CertificateException e) {
                            e.printStackTrace();
                        }
                    }
                    else if (Office_flag) {
                        _OfficeDocument = new TElOfficeDocument();
                        _OfficeDocument.open(des_path, false);

                        if(!_OfficeDocument.getSignable()) {
                            System.exit(1);
                            return;
                        }
                        signOffice = new Sign_Offices();
                        signOffice.signOffices();
                        showDialog(3);
                    }
                    else if (XML_flag) {
                        signXML = new Sign_XML();
                        try {
                            signXML.signXML();
                            showDialog(3);
                        }catch (Exception e) {
                            e.printStackTrace();
                        }
                    }
                    super.handleMessage(msg);
                    break;

                case DOSIGN:
                    src_path = edtSrc.getText() + "";
                    Log.e(TAG, src_path);
                    des_path = edtDes.getText() + "/" + edtNameFileSign.getText() + s + "";
                    Log.e(TAG, des_path);
                    signIn();
                    super.handleMessage(msg);
            }
        }
    }

    static {
        System.loadLibrary("tomikey-2003a");
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main_sign);

        context = MainSign.this;
        res = this.getResources();
        index = 0;

        File mPath = new File(Environment.getExternalStorageDirectory() + "");
        fileDialog = new FileDialog(MainSign.this, mPath);

        handler = new handler();
        progressDialog = new ProgressDialog(context);
        progressDialog.setCancelable(false);

        btnBrowseSrc = (Button) findViewById(R.id.btnBrowseSrc);
        btnBrowseDes = (Button) findViewById(R.id.btnBrowseDes);
        btnSign = (Button) findViewById(R.id.btnSign);
        btnLogin = (Button) findViewById(R.id.btnLogin);

        btnSignPDF = (Button) findViewById(R.id.btnSignPDF);
        btnSignOffices = (Button) findViewById(R.id.btnSignOffice);
        btnSignXML = (Button) findViewById(R.id.btnSignXml);

        edtSrc = (EditText) findViewById(R.id.edtSrc);
        edtDes = (EditText) findViewById(R.id.edtDes);

        edtLogin = (EditText) findViewById(R.id.edtPIN);
        edtCert = (EditText) findViewById(R.id.edtCert);
        ibLogout = (ImageButton) findViewById(R.id.ibLogout);
        ib_back = (ImageButton) findViewById(R.id.ib_back);
        viewLogin = (LinearLayout) findViewById(R.id.viewLogin);
        viewSign = (LinearLayout) findViewById(R.id.viewSign);
        viewChooseFileType = (LinearLayout) findViewById((R.id.viewChooseFileType));

        Log.e(TAG, "1_1");

        headSetReceiver = new BroadcastReceiver() {
            public void onReceive(Context context, Intent intent) {
                Log.e(TAG, "1_2");
                String action = intent.getAction();
                if (action.equals(Intent.ACTION_HEADSET_PLUG)) {
                    //headphone plugged
                    if(intent.getIntExtra("state", 0) == 1){
                        removeDialog(2);
                        Log.e(TAG, "1_3");
                        tryConnect();

                    }else{

                        showDialog(2);
                        Log.e(TAG, "1_4");
                        disConnect();
                        Log.e(TAG, "1_5");

                    }
                }
            }
        };
        registerReceiver(headSetReceiver, new IntentFilter(Intent.ACTION_HEADSET_PLUG));

        btnLogin.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                progressDialog.setMessage(res.getString(R.string.content_login));
                try {
                    String password = edtLogin.getText().toString();
                    if(password.compareTo("") != 0)
                    {
                        handler.sleep(0, SHOWPROGRESSDIALOG, "");
                        edtLogin.setText("");
                        if (!p11initialize(getApplicationContext())) {
                            showDialog(1);
                        }
                        else {
                            Log.e(TAG, "In LoginButton");
                            handler.sleep(0, VERIFYPASSWORD, password);
                        }

                    } else {
                        edtLogin.setText("");
                        showDialog(0);

                    }

                } catch (Exception e) {
                    e.printStackTrace();
                }

            }
        });

        ibLogout.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                Toast toast = Toast.makeText(getApplicationContext(), res.getString(R.string.logout), Toast.LENGTH_SHORT);
                toast.show();
                Log.e(TAG, "Loging out...1");
                session.logout();
                Log.e(TAG, "Loging out...2");
                Storage.closeSession(0);
                session = null;
                Log.e(TAG, "Loging out...3");
                Log.e(TAG, "Loging out...4");
                viewLogin.setVisibility(LinearLayout.VISIBLE);
                viewSign.setVisibility(LinearLayout.GONE);
                viewChooseFileType.setVisibility(LinearLayout.GONE);
                Log.e(TAG, "Loging out...5");
            }
        });

        edtCert.setOnClickListener(new View.OnClickListener() {
               @Override
               public void onClick(View v) {

                   int numOfCert = Storage.getCount();
                   String adapter[] = new String[numOfCert];
                   for (int i = 0; i < numOfCert; i++)
                   {
                       TElX509Certificate Cert;
                       Cert = Storage.getCertificate(i);
                       adapter[i] = Cert.getSubjectName().CommonName;
                       listCert.add(Cert);
                       Log.e(TAG, "in on cert list 0");
                   }

                   if(numOfCert != 0)
                   {

                       dialog = new Dialog(MainSign.this);
                       dialog.setContentView(R.layout.dialog_listcert);
                       dialog.setTitle(res.getString(R.string.title_certificates));
                       ListView lstView = (ListView) dialog.findViewById(R.id.lvCert);

                       CertCNArrayAdapter ad = new CertCNArrayAdapter(MainSign.this, R.layout.item_cert, adapter);
                       lstView.setAdapter(ad);
                       Log.e(TAG, "in on cert list 1");

                       lstView.setOnItemClickListener(new AdapterView.OnItemClickListener() {
                           @Override
                           public void onItemClick(AdapterView<?> arg0, View arg1,
                                                   int arg2, long arg3) {
                               Toast.makeText(getApplicationContext(), arg2 + "", Toast.LENGTH_SHORT).show();
                               dialog.dismiss();

                           }
                       });

                       dialog.show();
                   }

               }
           }
        );

        ib_back.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                Toast toast = Toast.makeText(getApplicationContext(), res.getString(R.string.back), Toast.LENGTH_SHORT);
                toast.show();
                viewLogin.setVisibility(LinearLayout.GONE);
                viewSign.setVisibility(LinearLayout.GONE);
                viewChooseFileType.setVisibility(LinearLayout.VISIBLE);
            }
        });

        btnBrowseSrc.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                //showFileChooser();
                try {
                    //fileDialog.setFileEndsWith(".txt");
                    fileDialog.addFileListener(new FileDialog.FileSelectedListener() {
                        public void fileSelected(File file) {
                            edtSrc.setText(file.toString());
                        }
                    });

                    fileDialog.setSelectDirectoryOption(false);
                }
                catch (Exception e) {
                    e.printStackTrace();
                }
                fileDialog.showDialog();
            }
        });

        btnBrowseDes.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                try {
                    fileDialog.addDirectoryListener(new FileDialog.DirectorySelectedListener() {
                        public void directorySelected(File directory) {
                            edtDes.setText(directory.toString());
                        }
                    });

                    fileDialog.setSelectDirectoryOption(true);

                } catch (Exception e) {
                    e.printStackTrace();
                }
                fileDialog.showDialog();
            }
        });

        btnSign.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                boolean check = true;
                s = edtSrc.getText().toString();
                if (edtSrc.getText().toString().compareTo("") == 0)  {
                    handler.sleep(0, SHOWINFO, res.getString(R.string.notice_check_filesign_location));
                }
                else if (edtDes.getText().toString().compareTo("") == 0) {
                    handler.sleep(0, SHOWINFO, res.getString(R.string.notice_choose_location_fielsigned));
                }
                else if (edtCert.getText().toString().compareTo("") == 0) {
                    handler.sleep(0, SHOWINFO, res.getString(R.string.notice_choose_certificate));
                }
                else {

                    s = s.substring(s.lastIndexOf("."));
                    if (PDF_flag) {
                        if (s.compareTo(".pdf") != 0) {
                            check = false;
                            handler.sleep(0, SHOWINFO, res.getString(R.string.warning_not_correct_pdffile));
                        }
                    }
                    else if (Office_flag) {
                        if (s.compareTo(".doc") != 0 && s.compareTo(".docx") != 0 && s.compareTo(".xls") != 0 && s.compareTo(".ppt") != 0) {
                            check= false;
                            handler.sleep(0, SHOWINFO, res.getString(R.string.warning_not_correct_officefile));
                        }
                    }
                    else if (XML_flag) {
                        if (s.compareTo(".xml") != 0) {
                            check = false;
                            handler.sleep(0, SHOWINFO, res.getString(R.string.warning_not_correct_xmlfile));
                        }
                    }

                    if (check) {
                        try {
                            LayoutInflater li = LayoutInflater.from(MainSign.this);
                            View promptsView = li.inflate(R.layout.name_file_sign, null);

                            AlertDialog.Builder alertDialogBuilder = new AlertDialog.Builder(
                                    MainSign.this);

                            alertDialogBuilder.setView(promptsView);

                            edtNameFileSign = (EditText) promptsView.findViewById(R.id.edtNameFileSign);
                            edtNameFileSign.setText("");

                            // set dialog message
                            alertDialogBuilder
                                    .setTitle(res.getString(R.string.name_file_sign))
                                    .setCancelable(false)
                                    .setPositiveButton("OK", new DialogInterface.OnClickListener() {
                                        public void onClick(DialogInterface dialog, int id) {
                                            if (edtNameFileSign.getText().toString().compareTo("") == 0) {
                                                handler.sleep(0, SHOWINFO, res.getString(R.string.notice_name_filesign));
                                            } else {
                                                dialog.cancel();
                                                progressDialog.setMessage(res.getString(R.string.signin));
                                                handler.sleep(0, SHOWPROGRESSDIALOG, "");
                                                //showProgressDialog();
                                                handler.sleep(100, DOSIGN, "");
                                            }
                                        }
                                    })
                                    .setNegativeButton("CANCEL",
                                            new DialogInterface.OnClickListener() {
                                                public void onClick(DialogInterface dialog, int id) {
                                                    dialog.cancel();
                                                }
                                            });

                            // create alert dialog
                            AlertDialog alertDialog = alertDialogBuilder.create();

                            // show it
                            alertDialog.show();

                            Log.e(TAG, "init");

                        } catch (Exception e) {
                            Log.e(TAG, "fail");
                            e.printStackTrace();
                        }
                    }

                }

            }
        });

        btnSignPDF.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                Toast toast = Toast.makeText(getApplicationContext(), res.getString(R.string.notice_selected_sign_pdf), Toast.LENGTH_SHORT);
                toast.show();
                tmp = new String [] {".pdf"};
                viewLogin.setVisibility(LinearLayout.GONE);
                viewSign.setVisibility(LinearLayout.VISIBLE);
                viewChooseFileType.setVisibility(LinearLayout.GONE);
                PDF_flag = true;
                Office_flag = false;
                XML_flag = false;

            }
        });

        btnSignOffices.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                Toast toast = Toast.makeText(getApplicationContext(), res.getString(R.string.notice_selected_sign_offices), Toast.LENGTH_SHORT);
                toast.show();
                tmp = new String [] {".doc", ".docx", ".xls", ".ppt"};
                viewLogin.setVisibility(LinearLayout.GONE);
                viewSign.setVisibility(LinearLayout.VISIBLE);
                viewChooseFileType.setVisibility(LinearLayout.GONE);
                PDF_flag = false;
                Office_flag = true;
                XML_flag = false;
            }
        });

        btnSignXML.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                Toast.makeText(getApplicationContext(), res.getString(R.string.notice_selected_sign_xml), Toast.LENGTH_SHORT).show();
                tmp = new String [] {".xml"};
                viewLogin.setVisibility(LinearLayout.GONE);
                viewSign.setVisibility(LinearLayout.VISIBLE);
                viewChooseFileType.setVisibility(LinearLayout.GONE);
                PDF_flag = false;
                Office_flag = false;
                XML_flag = true;
            }
        });

    }

    @Override
    protected Dialog onCreateDialog(int id) {
        switch(id)
        {
            case 0:
                Log.e(TAG, "1_6");
                return new AlertDialog.Builder(context)
                        .setTitle(res.getString(R.string.title_notify_enterpin))
                        .setMessage(res.getString(R.string.content_notify_enterpin))
                        .setPositiveButton("OK", new DialogInterface.OnClickListener() {
                            @Override
                            public void onClick(DialogInterface arg0, int arg1) {
                                arg0.dismiss();
                            }
                        })
                        .create();
            case 1:
                return new AlertDialog.Builder(context)
                        .setTitle(res.getString(R.string.title_init_error))
                        .setMessage(res.getString(R.string.content_init_error))
                        .setPositiveButton("OK", new DialogInterface.OnClickListener() {
                            @Override
                            public void onClick(DialogInterface arg0, int arg1) {
                                arg0.dismiss();
                            }
                        })
                        .create();
            case 2:
                return new AlertDialog.Builder(context)
                        .setTitle(res.getString(R.string.title_notify))
                        .setCancelable(false)
                        .setMessage(res.getString(R.string.notify_connect_audiopass))
                        .create();
            case 3:
                return new AlertDialog.Builder(context)
                        .setTitle(res.getString(R.string.title_complete))
                        .setMessage(res.getString(R.string.content_signed))
                        .setPositiveButton("OK", new DialogInterface.OnClickListener() {
                            @Override
                            public void onClick(DialogInterface arg0, int arg1) {
                                arg0.dismiss();
                            }
                        })
                        .create();
        }
        return super.onCreateDialog(id);
    }

    private void tryConnect()
    {
        progressDialog.setMessage(res.getString(R.string.connecting_audiopass));
        handler.sleep(0, SHOWPROGRESSDIALOG, "");
        new Thread() {
            public void run()
            {
                try {
                    if (!p11initialize(getApplicationContext())) {
                        isConnected = false;
                    } else {
                        isConnected = true;
                    }
                    Log.e(TAG, "init -1");

                    if (isConnected)
                    {
                        try {
                            Log.e(TAG, "init 0");
                            initialize();
                            Log.e(TAG, "init 1");
                        } catch (IOException e) {
                            Log.e(TAG, "init 2");
                            e.printStackTrace();
                        } catch (CertificateException e) {
                            Log.e(TAG, "init 3");
                            e.printStackTrace();
                        }
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                    isConnected = false;
                }
                handler.sleep(0, CLOSEPROGRESSDIALOG, "");
            }
        }.start();

    }

    private void disConnect()
    {
        Log.e(TAG, "1_7");
        handler.sleep(0, CLOSEPROGRESSDIALOG, "");

    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        session.logout();
        Storage.closeSession(0);
        session = null;
        unregisterReceiver(headSetReceiver);
    }

    public void myLogin(final String data) {
        Log.e(TAG, "log in ...1");
        new Thread() {
            public void run() {
                Log.e(TAG, "log in ...2");
                try {
                    try {

                        if (Login(data)) {
                            handler.sleep(0, LOGINSUCCESS, "");
                        }
                        else {
                            Log.e(TAG, "..........1");
                            handler.sleep(0, SHOWINFO, res.getString(R.string.content_notify_cannot_sign));
                        }
                    }
                    catch (IOException e1) {
                        e1.printStackTrace();
                        Log.e(TAG, "..........2");
                        handler.sleep(0, SHOWINFO, res.getString(R.string.content_notify_cannot_sign));
                    } catch (CertificateException e2) {
                        e2.printStackTrace();
                        Log.e(TAG, "..........3");
                        handler.sleep(0, SHOWINFO, res.getString(R.string.content_notify_cannot_sign));
                    } catch (Exception e) {
                        e.printStackTrace();
                        Log.e(TAG, "..........4");
                        handler.sleep(0, SHOWINFO, res.getString(R.string.content_notify_cannot_sign));
                    }
                } catch (Exception e) {
                    Log.e(TAG, "log in ...6");
                    e.printStackTrace();
                }
                handler.sleep(0, CLOSEPROGRESSDIALOG, "");
            }
        }.start();
    }

    public void signIn() {
        new Thread() {
            public void run() {
                try {
                    copyFileUsingFileStreams(src_path, des_path);
                    if (PDF_flag) {
                        signPDF = new Sign_PDF();
                        try {
                            if (signPDF.signPDF(des_path)){
                                handler.sleep(0,SHOWDIALOG, "");
                            };
                        } catch (IOException e) {
                            e.printStackTrace();
                        } catch (CertificateException e) {
                            e.printStackTrace();
                        }
                    }
                    else if (Office_flag) {
                        _OfficeDocument = new TElOfficeDocument();
                        _OfficeDocument.open(des_path, false);

                        if(!_OfficeDocument.getSignable()) {
                            System.exit(1);
                            return;
                        }
                        signOffice = new Sign_Offices();
                        if (signOffice.signOffices()) {
                            handler.sleep(0, SHOWDIALOG, "");
                        };
                    }
                    else if (XML_flag) {
                        signXML = new Sign_XML();
                        try {
                            if (signXML.signXML()) {
                                handler.sleep(0, SHOWDIALOG, "");
                            };
                        }catch (Exception e) {
                            e.printStackTrace();
                        }
                    }

                }catch (Exception e){
                    e.printStackTrace();
                }
                handler.sleep(0, CLOSEPROGRESSDIALOG, "");

            }
        }.start();
    }

    public void changeView() {
        viewLogin.setVisibility(LinearLayout.GONE);
        viewSign.setVisibility(LinearLayout.GONE);
        viewChooseFileType.setVisibility(LinearLayout.VISIBLE);
    }

    public  boolean p11initialize(Context _context) {

        try {
            AudioToken.initAudioToken(_context);
        } catch (AudioKeyExcep e2) {
            e2.printStackTrace();
            return false;
        }

        try {
            initialize();
            Log.e(TAG, "init 1");
        } catch (IOException e) {
            Log.e(TAG, "init 2");
            e.printStackTrace();
        } catch (CertificateException e) {
            Log.e(TAG, "init 3");
            e.printStackTrace();
        }

        return true;
    }

    public void initialize() throws IOException, CertificateException {
        SBUtils.setLicenseKey("85C8A078865CFEE46D8AFEDF0B003D848E8930C845FE805B08BB50AEDB9BAF19FAE5D2530D8C8685A949F42C1D2898BA26844D9EB885654348D32B47A2848C2719BCB8978F4529B3C7675A3DE36F28F0BE21BEECA47E4B08020A0173E8B67AF4F4508E36B3C872B4AEBA5394C5F7EA391B750619E26BB3B76186EF0C566652DA1E8D55F6632D7D06BA3DADEDE962A80A13994A702391AFABB190EAA16D999A918A9FECE7F745D414C2CFD419E8637FC9D76230BFC3E4F42B50A3F617E3480F12CFE8A5D2144C03F19492D4334FB43C1298945F457231C434872806E044B0937A8C6F0B80E9B041FD3DDDF58011A1EFA4FECA368265275CAA66D95CBA36B31108");
        JNI.initialize("/data/data/training.com.trandai.bananasignature/lib/libsbbjni.so");

        SBPDF.initialize();
        SBPDFSecurity.initialize();

        Document = new TElPDFDocument();
        Document.setOwnActivatedSecurityHandlers(true);
        PublicKeyHandler = new TElPDFPublicKeySecurityHandler();
        CertStorage = new TElMemoryCertStorage();

        String fileName = "/data/data/training.com.trandai.bananasignature/lib/libtomikey-2003a.so";

        Storage = new TElPKCS11CertStorage();
        Storage.setDLLName(fileName);
        Storage.open();
        Log.e(TAG, "In Login 1");

    }

    public boolean Login(String PIN) throws Exception {
        boolean b = false;

        //open session
        if (!Storage.getModule().getSlot(0).getTokenPresent()) {
            return false;
        }

        // Closing current session
        if (session != null)
        {
            session.logout();
            Storage.closeSession(0);
            session = null;
        }

        boolean RO = Storage.getModule().getSlot(0).getReadOnly();

        try
        {
            session = Storage.openSession(0, RO);
            Log.e(TAG, "In Login 2");
        }
        catch (Exception ex)
        {
            if (!RO)
                session = Storage.openSession(0, true);
            else{
                Log.e(TAG, "In Login 3");
                throw ex;
            }

        }

        //login
        try
        {
            session.login((int) SBPKCS11Base.utUser, PIN + "");
            Log.e(TAG, "In Login 4");
            b = true;
        }
        catch(Exception ex)
        {
            Log.e(TAG, "In Login 5");
            Storage.closeSession(0);
            session = null;
        }
        return b;
    }

    private static final int FILE_SELECT_CODE = 0;

    private void showFileChooser() {
        Intent intent = new Intent(Intent.ACTION_GET_CONTENT);
        intent.setType("*/*");
        intent.addCategory(Intent.CATEGORY_OPENABLE);

        try {
            startActivityForResult(
                    Intent.createChooser(intent, res.getString(R.string.choose_folder)), FILE_SELECT_CODE);
        } catch (android.content.ActivityNotFoundException ex) {
            // Potentially direct the user to the Market with a Dialog
            Toast.makeText(this, res.getString(R.string.intall_file_manager),
                    Toast.LENGTH_SHORT).show();
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        switch (requestCode) {
            case FILE_SELECT_CODE:
                if (resultCode == RESULT_OK) {
                    // Get the Uri of the selected file
                    Uri uri = data.getData();
                    Log.d(TAG, "File Uri: " + uri.toString());
                    // Get the path
                    String path = null;
                    try {
                        path = FileUtils.getPath(this, uri);
                    } catch (URISyntaxException e) {
                        e.printStackTrace();
                    }
                    Log.d(TAG, "File Path: " + path);
                    edtSrc.setText(path);
                    // Get the file instance
                    // File file = new File(path);
                    // Initiate the upload
                }
                break;

        }
        super.onActivityResult(requestCode, resultCode, data);
    }

    private static class FileUtils {
        public static String getPath(Context context, Uri uri) throws URISyntaxException {
            if ("content".equalsIgnoreCase(uri.getScheme())) {
                String[] projection = { "_data" };
                Cursor cursor = null;

                try {
                    cursor = context.getContentResolver().query(uri, projection, null, null, null);
                    int column_index = cursor.getColumnIndexOrThrow("_data");
                    if (cursor.moveToFirst()) {
                        return cursor.getString(column_index);
                    }
                } catch (Exception e) {
                    // Eat it
                }
            }
            else if ("file".equalsIgnoreCase(uri.getScheme())) {
                return uri.getPath();
            }

            return null;
        }
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        // Inflate the menu; this adds items to the action bar if it is present.
        getMenuInflater().inflate(R.menu.menu_main_sign, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        // Handle action bar item clicks here. The action bar will
        // automatically handle clicks on the Home/Up button, so long
        // as you specify a parent activity in AndroidManifest.xml.
        int id = item.getItemId();

        //noinspection SimplifiableIfStatement
        if (id == R.id.action_settings) {
            return true;
        }

        return super.onOptionsItemSelected(item);
    }

    private static void copyFileUsingFileStreams(String source, String dest){
        InputStream input = null;
        OutputStream output = null;
        try {
            File fsource = new File(source);
            File fdes = new File(dest);
            input = new FileInputStream(fsource);
            output = new FileOutputStream(fdes);
            byte[] buf = new byte[1024];
            int bytesRead;
            while ((bytesRead = input.read(buf)) > 0) {
                output.write(buf, 0, bytesRead);
            }
            input.close();
            output.close();
        } catch (Exception e) {
            Log.e(TAG, e.toString());
            e.printStackTrace();

        }
    }

    class CertCNArrayAdapter extends ArrayAdapter<String> {
        private  Context context;
        private int resources;
        private String[] cerObject;
        private LayoutInflater inflater;

        public CertCNArrayAdapter(Context context, int resource, String[] objects) {
            super(context, resource, objects);
            this.context = context;
            this.cerObject = objects;
            resources = resource;
            inflater = (LayoutInflater) context.getSystemService(Context.LAYOUT_INFLATER_SERVICE);
        }

        @Override
        public View getView(final int position, View convertView, ViewGroup parent) {
            // TODO Auto-generated method stub
            View v = inflater.inflate(resources, parent, false);
            TextView certName = (TextView) v.findViewById(R.id.labelCert);
            certName.setText(cerObject[position]);
            index = position;
            v.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View arg0) {
                    dialog.dismiss();
                    edtCert.setText(cerObject[position].toString());
                }
            });
            return v;
        }


    }

    private void showMessage(String msg)
    {
        if (null == msg || "" == msg)
            return;

        String title, button;
        button = "OK";
        title = res.getString(R.string.title_notify);
        new AlertDialog.Builder(this)
                .setTitle(title)
                .setCancelable(false)
                .setMessage(msg)
                .setPositiveButton(button, null).show();
    }
}

