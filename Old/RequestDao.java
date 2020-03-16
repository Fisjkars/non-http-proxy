package nope.persistance.dao;

import nope.persistance.entity.Request;
import org.hibernate.Session;

/**
 *
 * @author Maxime Escourbiac
 */
public class RequestDao extends NopeProxyDao {

    public static void saveOrUpdate(Request request) {
        Session session = getSession();
        session.getTransaction().begin();
        session.saveOrUpdate(request);
        session.getTransaction().commit();
    }

}
