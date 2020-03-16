
/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *   http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 *
 */

package nope.persistence.repository;

import java.util.List;

import org.hibernate.SessionFactory;
import org.hibernate.boot.registry.StandardServiceRegistry;
import org.hibernate.boot.registry.StandardServiceRegistryBuilder;
import org.hibernate.cfg.Configuration;

/**
 *
 * @author maxime
 * @param <T>
 */
public abstract class NopeRepository<T> {

  private static SessionFactory sessionFactory = null;

  /**
   * Get the Hibernate session factory.
   *
   * @return The single session factory.
   */
  protected static SessionFactory getSessionFactory() {
    if (sessionFactory == null) {
      try {
        Configuration cfg = new Configuration().configure("hibernate.cfg.xml");
        StandardServiceRegistryBuilder sb = new StandardServiceRegistryBuilder();
        sb.applySettings(cfg.getProperties());
        StandardServiceRegistry standardServiceRegistry = sb.build();
        sessionFactory = cfg.buildSessionFactory(standardServiceRegistry);
      } catch (Throwable th) {
        System.out.println("SessionFactory creation failed : " + th.getMessage());
        throw new ExceptionInInitializerError(th);
      }
    }
    return sessionFactory;
  }

  /**
   * Create an entity.
   *
   * @param entity Entity to create.
   * @return Entity created.
   */
  public abstract T create(T entity);

  /**
   * Update an entity.
   *
   * @param entity Entity to update.
   * @return Entity updated.
   */
  public abstract T update(T entity);

  /**
   * Delete an entity.
   *
   * @param entity Entity to delete.
   * @return
   */
  public abstract boolean delete(T entity);

  /**
   * Get an entity by id.
   *
   * @param id Entity ID.
   * @return The entity corresponding to the id.
   */
  public abstract T findById(long id);

  /**
   * Get all the entities.
   *
   * @return All the entities.
   */
  public abstract List<T> findAll();

}
