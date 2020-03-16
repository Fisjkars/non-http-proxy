package nope.persistance.dao;

import java.util.List;
import nope.persistance.entity.ListenerSetting;
import org.hibernate.Session;

/**
 *
 * @author Maxime ESCOURBIAC
 */
public class ListenerSettingDao extends NopeProxyDao {

    public static void save(ListenerSetting listenerSetting) {
        Session session = NopeProxyDao.getSession();
        session.getTransaction().begin();
        session.save(listenerSetting);
        session.getTransaction().commit();
        session.close();
    }

    public static void saveOrUpdate(ListenerSetting listenerSetting) {
        Session session = NopeProxyDao.getSession();
        session.getTransaction().begin();
        session.saveOrUpdate(listenerSetting);
        session.getTransaction().commit();
        session.close();
    }

    public static void delete(ListenerSetting listenerSetting) {
        Session session = NopeProxyDao.getSession();
        session.getTransaction().begin();
        session.delete(listenerSetting);
        session.getTransaction().commit();
        session.close();
    }

    public static List<ListenerSetting> findAll() {
        Session session = NopeProxyDao.getSession();
        List<ListenerSetting> list = (List<ListenerSetting>) session.createQuery("from ListenerSettingEntity").list();
        session.close();
        return list;
    }

    public static List<ListenerSetting> findBy(int lport, int sport, String sip, String cert, boolean ssl) {
        Session session = NopeProxyDao.getSession();
        List list = session.createQuery("from ListenerSettingEntity where sip = :sip and sport = :sport and lport = :lport and cert = :cert and ssl = :ssl")
                .setParameter("sip", sip)
                .setParameter("sport", sport)
                .setParameter("lport", lport)
                .setParameter("cert", cert)
                .setParameter("ssl", ssl)
                .list();
        session.close();
        return list;
    }
}
