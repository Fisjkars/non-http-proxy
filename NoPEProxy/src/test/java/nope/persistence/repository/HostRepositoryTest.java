/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package nope.persistence.repository;

import nope.persistence.entity.Host;
import static org.junit.Assert.assertNotNull;
import org.junit.Test;

/**
 *
 * @author maxime
 */
public class HostRepositoryTest {

  public HostRepositoryTest() {
  }

  /**
   * Test of create method, of class HostRepository.
   */
  @Test
  public void test() {
    HostRepository instance = new HostRepository();
    System.out.println("HostRepository:Create");
    Host entity = new Host();
    entity.setHost("TestCreate");
    Host result = instance.create(entity);
    System.out.println(result.getId());
    System.out.println(result.getHost());
    assertNotNull(result);
  }

}
