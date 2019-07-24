package josh.dao;

import org.hibernate.HibernateException;
import org.hibernate.SessionFactory;
import org.hibernate.cfg.Configuration;

/**
 * SQLite session factory. This class implement the singleton design pattern.
 */
public class SessionFactorySingleton {

    private static SessionFactory sessionFactory;

    public static SessionFactory getSessionFactory() throws HibernateException {
        if (sessionFactory == null) {
            String SQLString = "jdbc:sqlite:" + System.getProperty("user.home") + "/.NoPEProxy/requests.sqlite";
            Configuration cfg = new Configuration();
            cfg.configure();
            cfg.getProperties().setProperty("hibernate.connection.url", SQLString);
            sessionFactory = cfg.buildSessionFactory();
        }
        return sessionFactory;
    }
}
