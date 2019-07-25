package josh.service.timer;

import java.awt.Color;
import java.util.ArrayList;
import java.util.List;
import java.util.Queue;
import java.util.TimerTask;

import javax.swing.JTabbedPane;
import javax.swing.JTextField;

import org.hibernate.Session;

import jiconfont.icons.FontAwesome;
import jiconfont.swing.IconFontSwing;

import josh.dao.entity.RequestEntity;
import josh.dao.SessionFactorySingleton;

import zjosh.ui.utils.LogEntry;
import zjosh.ui.utils.NonHTTPTableModel;

/**
 * Update Database scheduled task.
 */
public class DatabaseUpdateTask extends TimerTask {

    private final Color nopeRed;
    private final Color nopePurple;
    private final Color nopeOrange;
    private final JTabbedPane tabs;
    private final JTextField searchTerm;
    private final NonHTTPTableModel tableModel;
    private final Queue<LogEntry> logEntries;
    private final Session session;

    /**
     * DatabaseUpdateTask constructor.
     *
     * @param logEntries Log entry queue.
     * @param tableModel Table model.
     * @param searchTerm Search Term.
     * @param tabs Tabs.
     */
    public DatabaseUpdateTask(Queue<LogEntry> logEntries, NonHTTPTableModel tableModel, JTextField searchTerm, JTabbedPane tabs) {
        this.nopeRed = new Color(214, 69, 65);
        this.nopePurple = new Color(142, 68, 173);
        this.nopeOrange = new Color(249, 191, 59);
        this.logEntries = logEntries;
        this.tableModel = tableModel;
        this.searchTerm = searchTerm;
        this.session = SessionFactorySingleton.getSessionFactory().openSession();
        this.tabs = tabs;
    }

    /**
     * Update Database scheduled task.
     */
    @Override
    public void run() {
        System.out.println("UpdateDBTask : Working on Queue");
        if (logEntries.peek() != null) {

            tabs.setIconAt(1, IconFontSwing.buildIcon(FontAwesome.HISTORY, 20, nopeRed));
            session.getTransaction().begin();
            LogEntry le;
            List<LogEntry> updated = new ArrayList<>();
            while ((le = logEntries.poll()) != null) {
                RequestEntity request = new RequestEntity(0, le.requestResponse, le.original, le.SrcIP, le.SrcPort, le.DstIP, le.DstPort, le.Direction, le.time.getTime(), le.Bytes);
                session.saveOrUpdate(request);
                le.Index = (long) request.getId();
                updated.add(le);
            }

            tabs.setIconAt(1, IconFontSwing.buildIcon(FontAwesome.HISTORY, 20, nopePurple));
            session.getTransaction().commit();
            for (LogEntry log : updated) {
                if (searchTerm.getText().equals("") || le.canAdd(searchTerm.getText())) {
                    tableModel.log.addFirst(log);
                    tableModel.fireTableRowsInserted(0, 0);
                }
            }
            tabs.setIconAt(1, IconFontSwing.buildIcon(FontAwesome.HISTORY, 20, nopeOrange));
        }
        System.out.println("UpdateDBTask : Finished on Queue");
    }
}
