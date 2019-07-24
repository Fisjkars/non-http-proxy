package zjosh.ui.utils;

import java.util.Calendar;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;
import org.hibernate.Session;
import josh.dao.SessionFactorySingleton;
import josh.dao.entity.ListenerSettingEntity;
import josh.dao.entity.RequestEntity;

public class ListenerDB {

    public static void add(ListenerSettingEntity ls) {
        Session s = SessionFactorySingleton.getSessionFactory().openSession();
        s.getTransaction().begin();
        s.save(ls);
        s.getTransaction().commit();
        s.close();

    }

    public static void updateSSL(ListenerSettingEntity ls, boolean ssl) {
        Session s = SessionFactorySingleton.getSessionFactory().openSession();
        List<ListenerSettingEntity> list = (List<ListenerSettingEntity>) s
                .createQuery("from ListenerSetting where sip = :sip and sport = :sport and lport = :lport and cert = :cert and ssl = :ssl")
                .setParameter("sip", ls.getSip())
                .setParameter("sport", ls.getSport())
                .setParameter("lport", ls.getLport())
                .setParameter("cert", ls.getCert())
                .setParameter("ssl", ls.isSsl())
                .list();
        if (list.size() >= 1) {
            s.getTransaction().begin();
            list.get(0).setSsl(ssl);
            s.update(list.get(0));
            s.getTransaction().commit();
        }
        s.close();

    }

    public static void remove(ListenerSettingEntity ls) {
        Session s = SessionFactorySingleton.getSessionFactory().openSession();
        List<ListenerSettingEntity> list = (List<ListenerSettingEntity>) s
                .createQuery("from ListenerSetting where sip = :sip and sport = :sport and lport = :lport and cert = :cert and ssl = :ssl")
                .setParameter("sip", ls.getSip())
                .setParameter("sport", ls.getSport())
                .setParameter("lport", ls.getLport())
                .setParameter("cert", ls.getCert())
                .setParameter("ssl", ls.isSsl())
                .list();
        if (list.size() >= 1) {
            s.getTransaction().begin();
            s.delete(list.get(0));
            s.getTransaction().commit();
        }
        s.close();
    }

    public static List<ListenerSettingEntity> restoreDB() {
        //HibHelper.getSessionFactory().openSession();

        Session s = SessionFactorySingleton.getSessionFactory().openSession();
        List<ListenerSettingEntity> list = (List<ListenerSettingEntity>) s.createQuery("from ListenerSetting").list();
        s.close();
        return list;

    }

}
