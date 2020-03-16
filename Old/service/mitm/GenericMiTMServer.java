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
import java.util.Calendar;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Random;
import java.util.Vector;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import josh.service.mitm.security.DynamicKeyStore;
import zjosh.nonHttp.SendData;
import zjosh.nonHttp.events.ProxyEvent;
import zjosh.nonHttp.events.ProxyEventListener;
import zjosh.ui.utils.InterceptData;
import zjosh.utils.events.PythonOutputEvent;
import zjosh.utils.events.PythonOutputEventListener;
import zjosh.utils.events.SendClosedEvent;
import zjosh.utils.events.SendClosedEventListener;

public class GenericMiTMServer implements Runnable, ProxyEventListener, PythonOutputEventListener, SendClosedEventListener {

    public static final int INTERCEPT_BOTH = 0;
    public static final int INTERCEPT_C2S = 1;
    public static final int INTERCEPT_S2C = 2;

    private boolean isSSL;
    private boolean isRunning;
    private boolean mangleWithPython;
    private boolean isInterceptOn;
    private int listenPort;
    private int serverPort;
    private int interceptDirection;
    private String serverAddress;
    private String certHostName;
    private String serverHostandIP;
    private Object svrSock;
    private Object cltSock;
    private Socket connectionSocket;

    private final InterceptData interceptc2s;
    private final InterceptData intercepts2c;
    private final List listeners;
    private final List pylisteners;
    private final IBurpExtenderCallbacks callbacks;
    private final Vector<Thread> threads;
    private final Vector<SendData> sends;
    private final HashMap<SendData, SendData> pairs;

    public GenericMiTMServer(boolean isSSL, IBurpExtenderCallbacks callbacks) {
        this.interceptc2s = new InterceptData(null);
        this.intercepts2c = new InterceptData(null);
        this.isSSL = isSSL;
        this.callbacks = callbacks;
        this.isInterceptOn = false;
        this.threads = new Vector<>();
        this.sends = new Vector<>();
        this.pairs = new HashMap<>();
        this.isSSL = false;
        this.isRunning = false;
        this.interceptDirection = 0;
        this.mangleWithPython = false;
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

    public synchronized void sendPyOutput(PythonOutputEvent event) {
        Iterator i = pylisteners.iterator();
        while (i.hasNext()) {
            ((PythonOutputEventListener) i.next()).pythonMessages(event);
        }
    }

    public boolean isMangleWithPython() {
        return this.mangleWithPython;
    }

    public void setMangleWithPython(boolean mangle) {
        this.mangleWithPython = mangle;
    }

    public void killThreads() {
        for (int i = 0; i < threads.size(); i++) {
            try {
                if (sends.get(i).isSSL()) {
                    ((SSLSocket) sends.get(i).sock).close();
                } else {
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
        if (this.serverAddress != null && this.serverPort != 0 && this.listenPort != 0) {
            try {
                if (isSSL) {
                    DynamicKeyStore test = new DynamicKeyStore();
                    String ksPath = test.generateKeyStore("changeit", this.certHostName);
                    KeyStore ks = KeyStore.getInstance("PKCS12");
                    ks.load(new FileInputStream(ksPath), "changeit".toCharArray());
                    KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
                    kmf.init(ks, "changeit".toCharArray());
                    SSLContext sc = SSLContext.getInstance("TLSv1.2");
                    sc.init(kmf.getKeyManagers(), null, null);
                    SSLServerSocketFactory ssf = sc.getServerSocketFactory();
                    svrSock = (SSLServerSocket) ssf.createServerSocket(this.listenPort);
                } else {
                    svrSock = new ServerSocket(this.listenPort);
                }

                while (true) {
                    try {
                        callbacks.printOutput("New MiTM Instance Created");
                        if (isSSL) {
                            connectionSocket = ((SSLServerSocket) svrSock).accept();
                        } else {
                            connectionSocket = ((ServerSocket) svrSock).accept();
                        }
                        connectionSocket.setSoTimeout(200);
                        connectionSocket.setReceiveBufferSize(2056);
                        connectionSocket.setSendBufferSize(2056);
                        connectionSocket.setKeepAlive(false);

                        InputStream inFromClient = connectionSocket.getInputStream();
                        DataOutputStream outToClient = new DataOutputStream(connectionSocket.getOutputStream());

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
                        System.out.println(connectionSocket.getPort() + " :: " + connectionSocket.getLocalPort() + " :: " + pairs.size());
                        SendData send = new SendData(this, true, isSSL); // bug... changed from false
                        send.addEventListener(GenericMiTMServer.this);
                        send.addPyEventListener(this);
                        send.addSendClosedEventListener(this);
                        send.Name = "c2s";
                        send.sock = connectionSocket;
                        send.in = inFromClient;
                        send.out = outToServer;

                        // Send data from server to Client
                        SendData getD = new SendData(this, false, isSSL);
                        getD.addEventListener(GenericMiTMServer.this);
                        getD.addPyEventListener(this);
                        getD.addSendClosedEventListener(this);
                        getD.Name = "s2c";
                        getD.sock = cltSock;
                        getD.in = inFromServer;
                        getD.out = outToClient;

                        send.doppel = getD;
                        getD.doppel = send;
                        sends.add(send);
                        sends.add(getD);
                        synchronized (this) {
                            System.out.println("Creating pairs");
                            pairs.put(send, getD);
                        }
                        Thread c2s = new Thread(send);
                        Thread s2c = new Thread(getD);
                        c2s.setName("SD-" + Calendar.getInstance().getTimeInMillis());
                        s2c.setName("SD-" + Calendar.getInstance().getTimeInMillis());
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
        } else {
            callbacks.printOutput("Ports and or Addresses are blank");
            this.isRunning = false;
        }
    }

    public void repeatToServer(byte[] repeat, int srcPort) {
        System.out.println("There are " + pairs.size() + " Threads for this connection");
        SendData lastAccessed = null;

        for (SendData sd : pairs.keySet()) {
            if (lastAccessed == null || lastAccessed.createTime < sd.createTime) {
                lastAccessed = sd;
            }
        }
        if (lastAccessed != null) {
            lastAccessed.repeatRequest(repeat);
        } else {
            System.out.println("All Connections closed...");
        }

    }

    public void repeatToClient(byte[] repeat, int srcPort) {
        System.out.println("There are " + pairs.size() + " Threads for this connection");
        SendData LastAccessed = null;
        for (SendData sd : pairs.values()) {
            if (LastAccessed == null || LastAccessed.createTime < sd.createTime) {
                LastAccessed = sd;
            }
        }

        if (LastAccessed != null) {
            LastAccessed.repeatRequest(repeat);
        } else {
            System.out.println("All Connections closed...");
        }
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

    public void setInterceptDir(int direction) {
        this.interceptDirection = direction;
    }

    public int getIntercetpDir() {
        return this.interceptDirection;
    }

    public void forwardC2SRequest(byte[] bytes) {
        interceptc2s.setData(bytes);
    }

    public void forwardS2CRequest(byte[] bytes) {
        intercepts2c.setData(bytes);
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

    public int getListenPort() {
        return listenPort;
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

    @Override
    public void closed(SendClosedEvent e) {
        synchronized (this) {
            Random rand = new Random();
            int to = rand.nextInt(1000);
            try {
                this.wait(to);
            } catch (InterruptedException e1) {
            }
            SendData tmp = (SendData) e.getSource();

            if (pairs.containsKey(tmp)) {
                System.out.println("first");
                pairs.remove(tmp);
            } else if (pairs.containsValue(tmp)) {
            }
        }

    }

    private synchronized void newDataEvent(ProxyEvent e) {
        ProxyEvent event = e;
        Iterator i = listeners.iterator();
        while (i.hasNext()) {
            ((ProxyEventListener) i.next()).dataReceived(event);
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
}
