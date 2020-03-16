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

package nope.persistance.entity;

import java.io.Serializable;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.Table;

/**
 * Host entity class.
 *
 * @author Fisjkars
 */
@Entity
@Table(name = "hosts")
public class Host implements Serializable {

  @Id
  @Column(name = "id")
  @GeneratedValue
  private int id;

  @Column(name = "host")
  private String host;

  /**
   * Host id.
   *
   * @return Host id.
   */
  public int getId() {
    return id;
  }

  /**
   * Host id.
   *
   * @param id Host id.
   */
  public void setId(int id) {
    this.id = id;
  }

  /**
   * Host name.
   *
   * @return Host name.
   */
  public String getHost() {
    return host;
  }

  /**
   * Host name.
   *
   * @param host Host name.
   */
  public void setHost(String host) {
    this.host = host;
  }
}
