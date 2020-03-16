/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 *
 */
package nope.persistance.dao;

import java.util.List;
import nope.persistance.entity.Host;
import org.hibernate.Session;

/**
 *
 * @author maxime
 */
public class HostDao extends NopeProxyDao {

    public static void save(Host listenerSetting) {
        Session session = NopeProxyDao.getSession();
        session.getTransaction().begin();
        session.save(listenerSetting);
        session.getTransaction().commit();
        session.close();
    }

    public static void saveOrUpdate(Host listenerSetting) {
        Session session = NopeProxyDao.getSession();
        session.getTransaction().begin();
        session.saveOrUpdate(listenerSetting);
        session.getTransaction().commit();
        session.close();
    }

    public static void delete(Host listenerSetting) {
        Session session = NopeProxyDao.getSession();
        session.getTransaction().begin();
        session.delete(listenerSetting);
        session.getTransaction().commit();
        session.close();
    }

    public static List<Host> findAll() {
        Session session = NopeProxyDao.getSession();
        List<Host> list = (List<Host>) session.createQuery("from HostEntity").list();
        session.close();
        return list;
    }
}
