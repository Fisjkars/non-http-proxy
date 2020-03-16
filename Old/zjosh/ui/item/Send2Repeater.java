package zjosh.ui.item;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.JMenuItem;

import zjosh.ui.NonHttpUI;

public class Send2Repeater {

    public static JMenuItem getItem(NonHttpUI ui) {
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
        return send2repeater;
    }
}
