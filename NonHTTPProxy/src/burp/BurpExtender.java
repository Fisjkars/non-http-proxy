package burp;

import java.awt.Component;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.List;

import javax.swing.JMenuItem;
import javax.swing.SwingUtilities;

import josh.ui.NonHttpUI;
import josh.utils.SharedBoolean;
import josh.utils.events.DNSEvent;
import josh.dnsspoof.UDPListener;

public class BurpExtender implements IBurpExtender, ITab, IContextMenuFactory {

    public IBurpExtenderCallbacks mCallbacks;

    private IExtensionHelpers helpers;
    private NonHttpUI ui;
    private final SharedBoolean sb = new SharedBoolean();
    private Thread thread = null;
    private UDPListener listener;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        mCallbacks = callbacks;
        helpers = mCallbacks.getHelpers();
        mCallbacks.setExtensionName("Non-HTTP Proxy");
        mCallbacks.registerContextMenuFactory(this);

        //Create our UI
        SwingUtilities.invokeLater(() -> {
            System.out.println("Building the UI...");
            ui = new NonHttpUI(mCallbacks, helpers, sb);

            if (ui != null && ui.DNSIP != null) {
                UDPListener.ADDRESS = ui.DNSIP.split("\\.");
            }

            listener = new UDPListener(Integer.parseInt(ui.getTxtDNSPort().getText()), sb);
            listener.Callbacks = mCallbacks;

            listener.addEventListener((DNSEvent e) -> {
                mCallbacks.issueAlert("DNSMiTM: DNS Server Stopped.");
                ui.DNSStopped();
            });

            listener.addTableEventListener(ui);

            ui.addEventListener((DNSEvent e) -> {
                if (!ui.isDNSRunning) {
                    mCallbacks.printOutput("Starting DNS Server");
                    if (e.getAddress() != null && !e.getAddress().equals("")) {
                        listener.ADDRESS = e.getAddress().split("\\.");
                    }
                    listener.setPort(e.getPort());

                    thread = new Thread(listener);
                    thread.start();
                    mCallbacks.issueAlert("DNSMiTM: DNS Server Started.");
                } else {
                    thread.interrupt();
                    listener.StopServer();
                    mCallbacks.issueAlert("DNSMiTM: DNS is Shutting Down");
                }
            });

            if (ui.getAutoStart()) {
                thread = new Thread(listener);
                thread.start();
                mCallbacks.issueAlert("DNSMiTM: DNS Server Started.");
            }
            mCallbacks.customizeUiComponent(ui);
            mCallbacks.addSuiteTab(BurpExtender.this);
        });

    }

    @Override
    public String getTabCaption() {
        return "Non-HTTP Proxy";
    }

    @Override
    public Component getUiComponent() {
        return ui;
    }

    private boolean shouldShow() {
        return (ui.ntbm.requestViewer.getComponent().isShowing()
                || ui.ntbm.originalViewer.getComponent().isShowing()
                || ui.intbm.requestViewer.getComponent().isShowing());
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation inv) {
        List<JMenuItem> nopes = new ArrayList<>();
        if (shouldShow()) {
            JMenuItem send2repeater = new JMenuItem("Send to Non-HTTP Proxy Repeater");
            send2repeater.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent arg0) {
                    byte[] message;
                    if (ui.ntbm.requestViewer.getComponent().isShowing()) {
                        message = ui.ntbm.requestViewer.getMessage();
                    } else if (ui.ntbm.originalViewer.getComponent().isShowing()) {
                        message = ui.ntbm.originalViewer.getMessage();
                    } else if (ui.intbm.requestViewer.getComponent().isShowing()) {
                        message = ui.intbm.requestViewer.getMessage();
                    } else {
                        return;
                    }
                    ui.repeater.setMessage(message, true);
                }
            });
            nopes.add(send2repeater);
        }
        return nopes;
    }

}
