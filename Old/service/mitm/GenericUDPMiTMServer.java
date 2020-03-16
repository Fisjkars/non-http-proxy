package josh.service.mitm;

import burp.IBurpExtenderCallbacks;

import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.ConnectException;
import java.net.DatagramSocket;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Vector;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import josh.service.mitm.security.DynamicKeyStore;
import zjosh.nonHttp.SendUDPData;
import zjosh.nonHttp.events.ProxyEvent;
import zjosh.nonHttp.events.ProxyEventListener;
import zjosh.ui.utils.InterceptData;
import zjosh.utils.events.PythonOutputEvent;
import zjosh.utils.events.PythonOutputEventListener;
import zjosh.utils.events.SendClosedEvent;
import zjosh.utils.events.SendClosedEventListener;

public class GenericUDPMiTMServer implements Runnable, ProxyEventListener, PythonOutputEventListener, SendClosedEventListener {

    public static final int INTERCEPT_BOTH = 0;
    public static final int INTERCEPT_C2S = 1;
    public static final int INTERCEPT_S2C = 2;

    private boolean isRunning;
    private boolean mangleWithPython;
    private boolean isInterceptOn;
    private int listenPort;
    private int serverPort;
    private int interceptDirection;
    private String serverAddress;
    private String serverHostandIP;
    private String certHostName;
    private Object svrSock;
    private Object cltSock;
    private Socket connectionSocket;

    private final boolean isSSL;
    private final InterceptData interceptc2s;
    private final InterceptData intercepts2c;
    private final List listeners;
    private final List pylisteners;
    private final IBurpExtenderCallbacks callbacks;
    private final Vector<Thread> threads;
    private final Vector<SendUDPData> sends;
    private final HashMap<SendUDPData, SendUDPData> pairs;

    public GenericUDPMiTMServer(boolean isSSL, IBurpExtenderCallbacks Callbacks) {
        this.interceptc2s = new InterceptData(null);
        this.intercepts2c = new InterceptData(null);
        this.isSSL = isSSL;
        this.isInterceptOn = false;
        this.isRunning = false;
        this.mangleWithPython = false;
        this.callbacks = Callbacks;
        this.interceptDirection = 0;
        this.threads = new Vector<>();
        this.sends = new Vector<>();
        this.pairs = new HashMap<>();
        this.listeners = new ArrayList();
        this.pylisteners = new ArrayList();
    }

    public static boolean available(int port) {
        boolean result = false;
        if (port >= 1 && port <= 65535) {
            ServerSocket ss = null;
            DatagramSocket ds = null;
            try {
                ss = new ServerSocket(port);
                ss.setReuseAddress(true);
                ds = new DatagramSocket(port);
                ds.setReuseAddress(true);
                result = true;
            } catch (IOException e) {
                //Don't really catch.
            } finally {
                if (ds != null) {
                    ds.close();
                }
                if (ss != null) {
                    try {
                        ss.close();
                    } catch (IOException e) {
                    }
                }
            }
        }
        return result;
    }

    public synchronized void addEventListener(ProxyEventListener listener) {
        listeners.add(listener);
    }

    public synchronized void removeEventListener(ProxyEventListener listener) {
        listeners.remove(listener);
    }

    public synchronized void addPyEventListener(PythonOutputEventListener listener) {
        pylisteners.add(listener);
    }

    public synchronized void removePyEventListener(PythonOutputEventListener listener) {
        pylisteners.remove(listener);
    }

    private synchronized void newDataEvent(ProxyEvent e) {
        ProxyEvent event = e;
        Iterator i = listeners.iterator();
        while (i.hasNext()) {
            ((ProxyEventListener) i.next()).dataReceived(event);
        }
    }

    public synchronized void sendPyOutput(PythonOutputEvent event) {
        Iterator i = pylisteners.iterator();
        while (i.hasNext()) {
            ((PythonOutputEventListener) i.next()).pythonMessages(event);
        }
    }

    private synchronized void interceptedEvent(ProxyEvent e, boolean isC2S) {
        ProxyEvent event = e;
        event.setMtm(this);
        Iterator i = listeners.iterator();
        while (i.hasNext()) {
            ((ProxyEventListener) i.next()).intercepted(event, isC2S);
        }
    }

    public boolean isMangleWithPython() {
        return this.mangleWithPython;
    }

    public void setMangleWithPython(boolean mangle) {
        this.mangleWithPython = mangle;
    }

    public void KillThreads() {
        for (int i = 0; i < threads.size(); i++) {
            try {
                if (sends.get(i).isSSL()) {
                    ((SSLSocket) sends.get(i).sock).shutdownInput();
                    ((SSLSocket) sends.get(i).sock).shutdownOutput();
                    ((SSLSocket) sends.get(i).sock).close();
                } else {
                    ((Socket) sends.get(i).sock).shutdownInput();
                    ((Socket) sends.get(i).sock).shutdownOutput();
                    ((Socket) sends.get(i).sock).close();
                }
            } catch (IOException e) {

            }
            sends.get(i).killme = true;
            threads.get(i).interrupt();
        }

        try {
            if (connectionSocket != null) {
                connectionSocket.close();
            }
            if (isSSL) {
                ((SSLServerSocket) svrSock).close();
            } else {
                ((ServerSocket) svrSock).close();
            }
        } catch (IOException e) {
        }
    }

    @Override
    public void run() {
        callbacks.printOutput("Starting New Server.");
        this.isRunning = true;
        if (this.serverAddress == null || this.serverPort == 0 | this.listenPort == 0) {
            callbacks.printOutput("Ports and or Addresses are blank");
            this.isRunning = false;
            return;
        }
        try {
            if (isSSL) {
                DynamicKeyStore test = new DynamicKeyStore();
                String ksPath = test.generateKeyStore("changeit", this.certHostName);
                KeyStore ks = KeyStore.getInstance("PKCS12");
                ks.load(new FileInputStream(ksPath), "changeit".toCharArray());
                KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
                kmf.init(ks, "changeit".toCharArray());
                SSLContext sc = SSLContext.getInstance("TLS");
                sc.init(kmf.getKeyManagers(), null, null);
                SSLServerSocketFactory ssf = sc.getServerSocketFactory();
                svrSock = (SSLServerSocket) ssf.createServerSocket(this.listenPort);
            } else {
                svrSock = new DatagramSocket(this.listenPort);
            }
            //svrSock = new ServerSocket(this.ListenPort);

            while (true) {
                try {
                    callbacks.printOutput("New MiTM Instance Created");
                    //System.out.println("Number of Threads is: " + threads.size());
                    if (isSSL) {
                        connectionSocket = ((SSLServerSocket) svrSock).accept();
                    }

                    connectionSocket.setSoTimeout(200);
                    connectionSocket.setReceiveBufferSize(2056);
                    connectionSocket.setSendBufferSize(2056);
                    connectionSocket.setKeepAlive(false);

                    InputStream inFromClient = connectionSocket.getInputStream();
                    DataOutputStream outToClient = new DataOutputStream(connectionSocket.getOutputStream());

                    //Object cltSock;
                    if (isSSL) {
                        SSLSocketFactory ssf = (SSLSocketFactory) SSLSocketFactory.getDefault();
                        cltSock = (SSLSocket) ssf.createSocket(this.serverAddress, this.serverPort);
                        ((SSLSocket) cltSock).setSoTimeout(200);
                        ((SSLSocket) cltSock).setReceiveBufferSize(2056);
                        ((SSLSocket) cltSock).setSendBufferSize(2056);
                        ((SSLSocket) cltSock).setKeepAlive(false);
                    } else {
                        cltSock = new Socket(this.serverAddress, this.serverPort);
                        ((Socket) cltSock).setSoTimeout(200);
                        ((Socket) cltSock).setReceiveBufferSize(2056);
                        ((Socket) cltSock).setSendBufferSize(2056);
                        ((Socket) cltSock).setKeepAlive(false);
                        serverHostandIP = ((Socket) cltSock).getRemoteSocketAddress().toString();
                        if (serverHostandIP != null && serverHostandIP.contains(":")) {
                            serverHostandIP = serverHostandIP.split(":")[0];
                        }

                        if (serverHostandIP.indexOf('/') == 0) {
                            serverHostandIP = serverHostandIP.split("/")[1];
                        }
                    }

                    DataOutputStream outToServer;

                    InputStream inFromServer;
                    if (isSSL) {
                        outToServer = new DataOutputStream(((SSLSocket) cltSock).getOutputStream());
                        inFromServer = ((SSLSocket) cltSock).getInputStream();
                    } else {
                        outToServer = new DataOutputStream(((Socket) cltSock).getOutputStream());
                        inFromServer = ((Socket) cltSock).getInputStream();
                    }

                    // Send data from client to server
                    SendUDPData send = new SendUDPData(this, true, false);
                    send.addEventListener(GenericUDPMiTMServer.this);
                    send.addPyEventListener(this);
                    send.addSendClosedEventListener(this);
                    send.sock = connectionSocket;
                    send.in = inFromClient;
                    send.out = outToServer;
                    send.Name = "c2s";

                    // Send data from server to Client
                    SendUDPData getD = new SendUDPData(this, false, isSSL);
                    getD.addEventListener(GenericUDPMiTMServer.this);
                    getD.addPyEventListener(this);
                    getD.addSendClosedEventListener(this);
                    getD.sock = cltSock;
                    getD.in = inFromServer;
                    getD.out = outToClient;
                    getD.Name = "s2c";

                    sends.add(send);
                    sends.add(getD);
                    pairs.put(send, getD);

                    Thread c2s = new Thread(send);
                    Thread s2c = new Thread(getD);

                    c2s.start();
                    s2c.start();
                    threads.add(c2s);
                    threads.add(s2c);

                } catch (ConnectException e) {
                    String message = e.getMessage();
                    System.out.println(e.getMessage());
                    if (message.equals("Connection refused")) {
                        callbacks.printOutput("Error: Connection Refused to " + this.serverAddress + ":" + this.serverPort);
                    } else {
                        callbacks.printOutput(e.getMessage());
                    }
                    connectionSocket.close();
                }

            }
        } catch (IOException | KeyManagementException | KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException | CertificateException ex) {
            callbacks.printOutput(ex.getMessage());

        }
        callbacks.printOutput("Main Thread Has Died but thats ok.");
        isRunning = false;

    }

    public boolean isRunning() {
        return this.isRunning;
    }

    public void setIntercept(boolean set) {
        this.isInterceptOn = set;
    }

    public boolean isInterceptOn() {
        return this.isInterceptOn;
    }

    public void setInterceptDirection(int direction) {
        this.interceptDirection = direction;
    }

    public int getInterceptDirection() {
        return this.interceptDirection;
    }

    public void forwardC2SRequest(byte[] bytes) {
        //System.out.println("Forwarding Request...");
        interceptc2s.setData(bytes);
    }

    public void forwardS2CRequest(byte[] bytes) {
        //System.out.println("Forwarding Request...");
        intercepts2c.setData(bytes);
    }

    @Override
    public void dataReceived(ProxyEvent e) {
        newDataEvent(e);
    }

    @Override
    public void intercepted(ProxyEvent e, boolean isC2S) {
        interceptedEvent(e, isC2S);

    }

    @Override
    public void pythonMessages(PythonOutputEvent e) {
        sendPyOutput(e);

    }

    private void KillSocks(SendUDPData sd) {
        try {
            if (sd.isSSL()) {
                ((SSLSocket) sd.sock).close();
            } else {
                ((Socket) sd.sock).close();
            }
        } catch (IOException e) {
        }
    }

    @Override
    public void closed(SendClosedEvent e) {
        SendUDPData tmp = (SendUDPData) e.getSource();
        if (pairs.containsKey(tmp)) {
            pairs.get(tmp).killme = true;
            //pairs.remove(tmp);

        } else if (pairs.containsValue(tmp)) {
            for (SendUDPData key : pairs.keySet()) {
                if (pairs.get(key).equals(tmp)) {
                    key.killme = true;
                    pairs.remove(key);
                    KillSocks(tmp);
                    KillSocks(key);
                }
            }
        }

    }

    public int getServerPort() {
        return serverPort;
    }

    public String getServerAddress() {
        return serverAddress;
    }

    public String getServerHostandIP() {
        return serverHostandIP;
    }

    public Socket getConnectionSocket() {
        return connectionSocket;
    }

    public InterceptData getInterceptc2s() {
        return interceptc2s;
    }

    public void setListenPort(int listenPort) {
        this.listenPort = listenPort;
    }

    public void setServerPort(int serverPort) {
        this.serverPort = serverPort;
    }

    public void setServerAddress(String serverAddress) {
        this.serverAddress = serverAddress;
    }

    public void setCertHostName(String certHostName) {
        this.certHostName = certHostName;
    }

}
