package josh.burp;

import burp.IBurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IContextMenuFactory;
import burp.IContextMenuInvocation;
import burp.IExtensionHelpers;
import burp.ITab;

import java.awt.Component;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.swing.JMenuItem;
import javax.swing.SwingUtilities;

import josh.service.udp.UDPListener;
import zjosh.ui.NonHttpUI;
import zjosh.ui.item.Send2Repeater;
import zjosh.utils.SharedBoolean;
import zjosh.utils.events.DNSEvent;

/**
 * Non-HTTP Proxy main class.
 */
public class BurpExtender implements IBurpExtender, ITab, IContextMenuFactory {

    private IBurpExtenderCallbacks mCallbacks;
    private IExtensionHelpers helpers;
    private NonHttpUI ui;
    private Thread thread = null;
    private UDPListener listener;

    private final SharedBoolean sb = new SharedBoolean();

    /**
     * This method is invoked when the extension is loaded. It registers an
     * instance of the IBurpExtenderCallbacks interface, providing methods that
     * may be invoked by the extension to perform various actions.
     *
     * @param callbacks An IBurpExtenderCallbacks object
     */
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        mCallbacks = callbacks;
        helpers = mCallbacks.getHelpers();
        mCallbacks.setExtensionName("Non-HTTP Proxy");
        mCallbacks.registerContextMenuFactory(this);

        SwingUtilities.invokeLater(() -> {
            System.out.println("Building the UI...");
            ui = new NonHttpUI(mCallbacks, helpers, sb);
            if (ui != null && ui.DNSIP != null) {
                UDPListener.ADDRESS = ui.DNSIP.split("\\.");
            }

            System.out.println("Setting up the UDP listener...");
            listener = new UDPListener(Integer.parseInt(ui.getTxtDNSPort().getText()), sb, mCallbacks);

            listener.addEventListener((DNSEvent e) -> {
                mCallbacks.issueAlert("DNSMiTM: DNS Server Stopped.");
                ui.DNSStopped();
            });

            listener.addTableEventListener(ui);

            ui.addEventListener((DNSEvent e) -> {
                if (!ui.isDNSRunning) {
                    mCallbacks.printOutput("Starting DNS Server");
                    if (e.getAddress() != null && !e.getAddress().equals("")) {
                        UDPListener.ADDRESS = e.getAddress().split("\\.");
                    }
                    listener.setPort(e.getPort());

                    thread = new Thread(listener);
                    thread.start();
                    mCallbacks.issueAlert("DNSMiTM: DNS Server Started.");
                } else {
                    thread.interrupt();
                    listener.stop();
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

    /**
     * Burp uses this method to obtain the caption that should appear on the
     * custom tab when it is displayed.
     *
     * @return The caption that should appear on the custom tab when it is
     * displayed.
     */
    @Override
    public String getTabCaption() {
        return "Non-HTTP Proxy";
    }

    /**
     * urp uses this method to obtain the component that should be used as the
     * contents of the custom tab when it is displayed.
     *
     * @return The component that should be used as the contents of the custom
     * tab when it is displayed.
     */
    @Override
    public Component getUiComponent() {
        return ui;
    }

    /**
     * This method will be called by Burp when the user invokes a context menu
     * anywhere within Burp.
     *
     * @param invocation An object that implements the IContextMenuInvocation
     * interface, which the extension can query to obtain details of the context
     * menu invocation.
     * @return A list of custom menu items (which may include sub-menus,
     * checkbox menu items, etc.) that should be displayed. Extensions may
     * return null from this method, to indicate that no menu items are required
     */
    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        return (ui.ntbm.requestViewer.getComponent().isShowing()
                || ui.ntbm.originalViewer.getComponent().isShowing()
                || ui.intbm.requestViewer.getComponent().isShowing())
                ? new ArrayList<>(Arrays.asList(Send2Repeater.getItem(ui))) : new ArrayList<>();
    }

}
