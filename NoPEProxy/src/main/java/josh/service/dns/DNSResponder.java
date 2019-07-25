package josh.service.dns;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Properties;

import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.InitialDirContext;
import josh.service.udp.UDPListener;

import zjosh.utils.events.DNSTableEvent;
import zjosh.utils.events.DNSTableEventListener;

public class DNSResponder implements Runnable {

    private final DatagramPacket packet;
    private final UDPListener udpListener;

    public DNSResponder(DatagramPacket packet, UDPListener udpListener) {
        this.packet = packet;
        this.udpListener = udpListener;
    }

    @Override
    public void run() {
        String ip = packet.getAddress().getHostAddress();

        //Create a copy of the packet.
        byte[] copy = new byte[packet.getLength()];
        System.arraycopy(packet.getData(), 0, copy, 0, packet.getLength());

        //Extract the hostname from the packet.
        String packetHostname = extractHostname(copy);

        //Extract the hostname from the ip.
        String addressHostname = "";
        try {
            InetAddress inetAdd = InetAddress.getByName(ip);
            addressHostname = inetAdd.getHostName();
        } catch (UnknownHostException e1) {
            udpListener.getCallbacks().printError(e1.getMessage());
        }

        byte[] dnsResp = new byte[1024];

        int i = 0;
        //dns transaction ID
        dnsResp[i++] = copy[0];
        dnsResp[i++] = copy[1];

        //OpCodes
        dnsResp[i++] = (byte) 0x81;
        dnsResp[i++] = (byte) 0x80;

        dnsResp[i++] = copy[4];
        dnsResp[i++] = copy[5];
        dnsResp[i++] = copy[4];
        dnsResp[i++] = copy[5];

        dnsResp[i++] = 0;
        dnsResp[i++] = 0;
        dnsResp[i++] = 0;
        dnsResp[i++] = 0;

        for (int j = i; j < copy.length; j++) {
            dnsResp[i++] = copy[j];
        }

        dnsResp[i++] = (byte) 0xc0;
        dnsResp[i++] = (byte) 0x0c;
        dnsResp[i++] = 0;
        dnsResp[i++] = 1;
        dnsResp[i++] = 0;
        dnsResp[i++] = 1;
        dnsResp[i++] = 0;
        dnsResp[i++] = 0;
        dnsResp[i++] = 0;
        dnsResp[i++] = (byte) 0x3c;
        dnsResp[i++] = 0;
        dnsResp[i++] = 4;

        List<String> hosts = readHosts();
        Boolean override = false;
        String returnIP = UDPListener.ADDRESS[0] + "." + UDPListener.ADDRESS[1] + "." + UDPListener.ADDRESS[2] + "." + UDPListener.ADDRESS[3];

        for (String line : hosts) {
            if (line.contains(packetHostname) && !line.startsWith("#")) {
                String hostIP = line.split(" ")[0];
                if (hostIP.matches("[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}")) {
                    returnIP = hostIP;
                    String[] hostIPOcts = hostIP.split("\\.");
                    dnsResp[i++] = (byte) Long.parseLong(hostIPOcts[0]);
                    dnsResp[i++] = (byte) Long.parseLong(hostIPOcts[1]);
                    dnsResp[i++] = (byte) Long.parseLong(hostIPOcts[2]);
                    dnsResp[i++] = (byte) Long.parseLong(hostIPOcts[3]);
                    override = true;
                    break;
                }
            }
        }

        if (UDPListener.ADDRESS != null && !override && udpListener.getSb().getDefault()) {
            dnsResp[i++] = (byte) Long.parseLong(UDPListener.ADDRESS[0]);
            dnsResp[i++] = (byte) Long.parseLong(UDPListener.ADDRESS[1]);
            dnsResp[i++] = (byte) Long.parseLong(UDPListener.ADDRESS[2]);
            dnsResp[i++] = (byte) Long.parseLong(UDPListener.ADDRESS[3]);
        } else {
            try {

                //Get IP adresses from dns.
                Properties env = new Properties();
                env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.dns.DnsContextFactory");
                env.put(Context.PROVIDER_URL, "dns://" + UDPListener.EXTERNAL_DNS);
                InitialDirContext idc = new InitialDirContext(env);
                Attribute attr = idc.getAttributes(packetHostname, new String[]{"A"}).get("A");

                List<String> ipAddresses = new ArrayList<>();
                if (attr != null) {
                    for (int k = 0; k < attr.size(); k++) {
                        ipAddresses.add((String) attr.get(k));
                    }
                }

                boolean found = false;

                for (String address : ipAddresses) {
                    InetAddress inetaddress = InetAddress.getByName(address);
                    if (inetaddress instanceof Inet4Address) {
                        byte[] octs = inetaddress.getAddress();
                        dnsResp[i++] = octs[0];
                        dnsResp[i++] = octs[1];
                        dnsResp[i++] = octs[2];
                        dnsResp[i++] = octs[3];
                        returnIP = (octs[0] & 0xFF) + "." + (octs[1] & 0xFF) + "." + (octs[2] & 0xFF) + "." + (octs[3] & 0xFF);
                        found = true;
                        break;
                    }
                }

                if (!found) {
                    returnIP = "Unknown Hostname";
                    fireTableEvent(packetHostname, ip, addressHostname, returnIP);
                    return;
                }

            } catch (UnknownHostException | NamingException e) {
                returnIP = "Error Resolvng Hostname";
                fireTableEvent(packetHostname, ip, addressHostname, returnIP);
                return;
            }
        }

        fireTableEvent(packetHostname, ip, addressHostname, returnIP);

        byte[] ans = new byte[i];
        System.arraycopy(dnsResp, 0, ans, 0, i);

        try {
            DatagramPacket updResp = new DatagramPacket(ans, ans.length, packet.getAddress(), packet.getPort());
            udpListener.getDatagramSocket().send(updResp);
        } catch (IOException e) {
            udpListener.getCallbacks().printError(e.getMessage());
        } catch (Exception ex) {
            udpListener.getCallbacks().printError(ex.getMessage());
        }
    }

    private synchronized void fireTableEvent(String Domain, String ClientIP, String HostName, String ResponseIp) {
        DNSTableEvent event = new DNSTableEvent(this);
        event.setClientIP(ClientIP);
        event.setDomain(Domain);
        event.setHostName(HostName);
        event.setResponseIp(ResponseIp);
        Iterator<DNSTableEventListener> i = udpListener.getDnslisteners().iterator();
        while (i.hasNext()) {
            i.next().NewDomainRequest(event);
        }
    }

    private List<String> readHosts() {
        List<String> hosts = new ArrayList<>();

        String path = System.getProperty("user.home");
        String file = path + "/.NoPEProxy/hosts.txt";
        File f = new File(file);

        if (f.exists()) {
            try {
                Path p = Paths.get(file);
                BufferedReader reader = Files.newBufferedReader(p);
                String host;
                while ((host = reader.readLine()) != null) {
                    hosts.add(host);
                }
            } catch (IOException e) {
                hosts = new ArrayList<>();
            }
        }
        return hosts;
    }

    private String extractHostname(byte[] copy) {
        String hostname = "";
        for (int k = 12; k < copy.length;) {
            if (copy[k] == 0) {
                hostname = hostname.substring(0, hostname.length() - 1); //removes the last period
                break;
            }
            int limit = k + copy[k++] + 1;
            for (; k < limit && k < copy.length; k++) {
                hostname += "" + (char) copy[k];
            }
            hostname += ".";
        }
        return hostname;
    }
}
