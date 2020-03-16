
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
import java.util.Base64;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.Table;

/**
 * Request entity.
 *
 * @author Fisjkars.
 */
@Entity
@Table(name = "requests")
public class Request implements Serializable {

  @Id
  @Column(name = "id")
  @GeneratedValue
  private int id;

  @Column(name = "alt_id")
  private int altId;

  @Column(name = "data")
  private String data;

  @Column(name = "original")
  private String original;

  @Column(name = "srcip")
  private String srcIp;

  @Column(name = "dstip")
  private String dstIp;

  @Column(name = "bytes")
  private int bytes;

  @Column(name = "srcport")
  private int srcPort;
  @Column(name = "dstport")
  private int dstPort;

  @Column(name = "date")
  private Long date;

  @Column(name = "direction")
  private String direction;

  @Column(name = "data_str")
  private String dataStr;

  @Column(name = "original_str")
  private String originalStr;

  /**
   * Public Default constructor.
   */
  public Request() {
  }

  /**
   * RequestEntity constructor.
   *
   * @param index Request Alt Id.
   * @param requestResponse Request response data.
   * @param time Request date.
   * @param original Original Data.
   * @param srcIp Request source ip.
   * @param srcPort Request source port.
   * @param dstPort Request destination port.
   * @param direction Request direction.
   * @param dstIP Destination IP.
   * @param bytes Request size.
   */
  public Request(int index, byte[] requestResponse, byte[] original, String srcIp, int srcPort, String dstIP, int dstPort, String direction, Long time, int bytes) {
    this.altId = index;
    this.data = Base64.getEncoder().encodeToString(requestResponse);
    this.original = Base64.getEncoder().encodeToString(original);
    this.srcIp = srcIp;
    this.srcPort = srcPort;
    this.dstIp = dstIP;
    this.dstPort = dstPort;
    this.direction = direction;
    this.date = time;
    this.bytes = bytes;
    this.originalStr = new String(original).replaceAll("[^a-zA-Z0-9~!@#$%^&*()_+`\\-=,./<>?\\s]", "");
    this.dataStr = new String(requestResponse).replaceAll("[^a-zA-Z0-9~!@#$%^&*()_+`\\-=,./<>?\\s]", "");
  }

  /**
   * Request ID.
   *
   * @return Request ID.
   */
  public int getId() {
    return id;
  }

  /**
   * Request Alt Id.
   *
   * @return Request Alt Id.
   */
  public int getAlt_id() {
    return altId;
  }

  /**
   * Request response data.
   *
   * @return Request response data.
   */
  public byte[] getData() {
    if (data == null) {
      return null;
    } else {
      return Base64.getDecoder().decode(data);
    }

  }

  /**
   * Original Data.
   *
   * @return Original Data.
   */
  public byte[] getOriginal() {
    if (original == null) {
      return null;
    } else {
      return Base64.getDecoder().decode(original);
    }
  }

  /**
   * Request source ip.
   *
   * @return Request source ip.
   */
  public String getSrcIp() {
    return srcIp;
  }

  /**
   * Destination IP.
   *
   * @return Destination IP.
   */
  public String getDstIp() {
    return dstIp;
  }

  /**
   * Request size.
   *
   * @return Request size.
   */
  public int getBytes() {
    return bytes;
  }

  /**
   * Request source port.
   *
   * @return Request source port.
   */
  public int getSrcPort() {
    return srcPort;
  }

  /**
   * Request destination port.
   *
   * @return Request destination port.
   */
  public int getDstPort() {
    return dstPort;
  }

  /**
   * Request date.
   *
   * @return Request date.
   */
  public Long getDate() {
    return date;
  }

  /**
   * Request direction.
   *
   * @return Request direction.
   */
  public String getDirection() {
    return direction;
  }

  /**
   * Request id.
   *
   * @param id Request id.
   */
  public void setId(int id) {
    this.id = id;
  }

  /**
   * Request Alt Id.
   *
   * @param altId Request Alt Id.
   */
  public void setAlt_id(int altId) {
    this.altId = altId;
  }

  /**
   * Request response data.
   *
   * @param data Request response data.
   */
  public void setData(String data) {
    this.data = data;
  }

  /**
   * Original Data.
   *
   * @param original Original Data.
   */
  public void setOriginal(String original) {
    this.original = original;
  }

  /**
   * Request source ip.
   *
   * @param srcIp Request source ip.
   */
  public void setSrcIp(String srcIp) {
    this.srcIp = srcIp;
  }

  /**
   * Destination IP.
   *
   * @param dstIp Destination IP.
   */
  public void setDstIp(String dstIp) {
    this.dstIp = dstIp;
  }

  /**
   * Request size.
   *
   * @param bytes Request size.
   */
  public void setBytes(int bytes) {
    this.bytes = bytes;
  }

  /**
   * Request source port.
   *
   * @param srcPort Request source port.
   */
  public void setSrcPort(int srcPort) {
    this.srcPort = srcPort;
  }

  /**
   * Request destination port.
   *
   * @param dstPort Request destination port.
   */
  public void setDstPort(int dstPort) {
    this.dstPort = dstPort;
  }

  /**
   * Request date.
   *
   * @param date Request date.
   */
  public void setDate(Long date) {
    this.date = date;
  }

  /**
   * Request direction.
   *
   * @param direction Request direction.
   */
  public void setDirection(String direction) {
    this.direction = direction;
  }

  /**
   * Request String data.
   *
   * @return Request String data.
   */
  public String getDataStr() {
    return dataStr;
  }

  /**
   * Request String data.
   *
   * @param dataStr Request String data.
   */
  public void setDataStr(String dataStr) {
    this.dataStr = dataStr;
  }

  /**
   * Request Original data.
   *
   * @return Request Original data.
   */
  public String getOriginalStr() {
    return originalStr;
  }

  /**
   * Request Original data.
   *
   * @param originalStr Request Original data.
   */
  public void setOriginalStr(String originalStr) {
    this.originalStr = originalStr;
  }

}
