package josh.service.udp;

import josh.service.dns.DNSResponder;
import burp.IBurpExtenderCallbacks;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Properties;

import zjosh.utils.SharedBoolean;
import zjosh.utils.events.DNSEvent;
import zjosh.utils.events.DNSTableEventListener;
import zjosh.utils.events.UDPEventListener;

/**
 * UDP Listener class.
 */
public class UDPListener implements Runnable {

    public static String[] ADDRESS;
    public static int INTERFACE_NUMBER = 0;
    public static String EXTERNAL_DNS = "";

    private int port;
    private boolean stop;
    private DatagramSocket datagramSocket;

    private final SharedBoolean sb;
    private final IBurpExtenderCallbacks callbacks;
    private final List<UDPEventListener> udplisteners;
    private final List<DNSTableEventListener> dnslisteners;

    public UDPListener(int port, SharedBoolean sb, IBurpExtenderCallbacks callbacks) {
        this.port = port;
        this.sb = sb;
        this.stop = false;
        this.port = 5351;
        this.callbacks = callbacks;
        this.udplisteners = new ArrayList<>();
        this.dnslisteners = new ArrayList<>();
    }

    @Override
    public void run() {
        stop = false;
        updateInterface();

        if (ADDRESS != null && !ADDRESS[0].equals("---")) {
            callbacks.printOutput("DNSMiTM: Responding IP Address is " + ADDRESS[0] + "." + ADDRESS[1] + "." + ADDRESS[2] + "." + ADDRESS[3]);

            try {
                callbacks.printOutput("Using port: " + this.port);
                datagramSocket = new DatagramSocket(this.port);
                while (!stop) {
                    try {
                        byte[] buffer = new byte[1024];
                        DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
                        datagramSocket.receive(packet);
                        new Thread(new DNSResponder(packet, this)).start();
                    } catch (SocketTimeoutException ex) {
                        //Just continue to receive data.
                    } catch (IOException e) {
                        callbacks.printError(e.getMessage());
                    }
                }
                fireEvent();
            } catch (SocketException e) {
                callbacks.printError(e.getMessage());
                System.out.println("Could not start DNS");
                fireEvent();
            }
        } else {
            System.out.println("Could not start DNS");
            fireEvent();
        }
    }

    public synchronized void addEventListener(UDPEventListener listener) {
        udplisteners.add(listener);
    }

    public synchronized void removeEventListener(UDPEventListener listener) {
        udplisteners.remove(listener);
    }

    public synchronized void addTableEventListener(DNSTableEventListener listener) {
        dnslisteners.add(listener);
    }

    public synchronized void removeTableEventListener(DNSTableEventListener listener) {
        dnslisteners.remove(listener);
    }

    public void stop() {
        if (datagramSocket != null) {
            datagramSocket.close();
            stop = true;
        }
    }

    public boolean isStopped() {
        return stop;
    }

    public DatagramSocket getDatagramSocket() {
        return datagramSocket;
    }

    public int getPort() {
        return port;
    }

    public void setPort(int port) {
        this.port = port;
    }

    public IBurpExtenderCallbacks getCallbacks() {
        return callbacks;
    }

    public SharedBoolean getSb() {
        return sb;
    }

    public List<UDPEventListener> getUdplisteners() {
        return udplisteners;
    }

    public List<DNSTableEventListener> getDnslisteners() {
        return dnslisteners;
    }

    private synchronized void fireEvent() {
        DNSEvent event = new DNSEvent(this);
        Iterator<UDPEventListener> i = udplisteners.iterator();
        while (i.hasNext()) {
            i.next().UDPDown(event);
        }
    }

    private void updateInterface() {
        try {
            File f = new File(System.getProperty("user.home") + "/.NoPEProxy/dns.properties");
            Properties config = new Properties();
            if (f.exists()) {
                //Load previous config.
                config.load(new FileInputStream(f));
            } else {
                //Create the configuration file.
                f.getParentFile().mkdirs();
                config.load(ClassLoader.getSystemResourceAsStream("dns.properties"));
                config.store(new FileOutputStream(f), null);
            }

            //Extact properties.
            INTERFACE_NUMBER = Integer.parseInt(config.getProperty("interface", "0"));
            EXTERNAL_DNS = config.getProperty("extDNS", "8.8.8.8");
        } catch (IOException | NumberFormatException ex) {
            callbacks.printError(ex.getMessage());
        }
    }

}
