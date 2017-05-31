// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet
package models.iptables

// Scala
import org.junit.runner.RunWith
import org.scalatest.{FunSuite, Matchers}
import org.scalatest.junit.JUnitRunner

// project
import core._


@RunWith(classOf[JUnitRunner])
class DriverSuite extends FunSuite with Matchers
                                   with SymnetCustomMatchers {

  test("no iptables, just routing") {
    val ips = """
      eth0 15.15.15.15
      eth1 192.168.0.1
    """
    val rt = """
      192.168.0.0/24 eth1
      0.0.0.0/0 eth0
    """
    val ipt = ""

    val (success, _) = new Driver(ips, rt, ipt, "eth0").run()
    success should have length (4)
      // * 1 to local process (15.15.15.15)
      // * 1 to local process (192.168.0.1)
      // * 1 to subnet 192.168.0.0/24
      // * 1 to default gateway
      //    FIXME: Fix it to not allow forwarding on the output port that
      //    corresponds to the input port it has entered the device.

  }

  test("one way firewall") {
    val ips = """
      eth0 15.15.15.15
      eth1 192.168.0.1
    """
    val rt = """
      192.168.0.0/24 eth1
      0.0.0.0/0 eth0
    """
    val ipt = """
      <<filter>>
      <FORWARD:DROP>
        -i eth0 -j ACCEPT
    """

    {
      val (success, _) = new Driver(ips, rt, ipt, "eth0").run()
      success should have length (4)
        // FIXME: See test 'no iptables, just routing' above.
    }
    {
      val (success, _) = new Driver(ips, rt, ipt, "eth1").run()
      success should have length (2)
        // Just to local processes.
    }
  }
}
