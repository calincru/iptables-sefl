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

// 3rd party:
// -> Symnet
import org.change.v2.analysis.expression.concrete._
import org.change.v2.analysis.expression.concrete.nonprimitive._
import org.change.v2.analysis.processingmodels.instructions._
import org.change.v2.util.canonicalnames._

// project
import core._
import extensions.conntrack.ConnectionState
import types.net.Ipv4
import virtdev.SymnetFacade


@RunWith(classOf[JUnitRunner])
class DriverSuite extends FunSuite with Matchers
                                   with SymnetCustomMatchers {

  private lazy val ipMirror = {
    import virtdev.devices.RegularVirtualDevice

    new RegularVirtualDevice[Unit]("ip-mirror", 1, 1, ()) {
      override def portInstructions = Map(inputPort(0) -> InstructionBlock(
        // Check that IP header is allocated and swap addresses.
        Allocate("tmp"),
        Assign("tmp", :@(IPSrc)),
        Assign(IPSrc, :@(IPDst)),
        Assign(IPDst, :@("tmp")),

        Assign("tmp", :@(TcpSrc)),
        Assign(TcpSrc, :@(TcpDst)),
        Assign(TcpDst, :@("tmp")),

        Deallocate("tmp"),
        Forward(outputPort(0))
      ))
    }
  }

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
        // Same as above.
    }
    {
      val (success, _) = new Driver(ips, rt, ipt, "eth1").run()
      success should have length (2)
        // Just to local processes.
    }
  }

  test("simple snat") {
    val ips = """
      eth0 15.15.15.15
      eth1 192.168.0.1
    """
    val rt = """
      192.168.0.0/24 eth1
      0.0.0.0/0 eth0
    """
    val ipt = """
      <<nat>>
      <POSTROUTING:ACCEPT>
        -s 192.168.0.0/24 -p tcp -j SNAT --to-source 15.15.15.15:5000-10000
    """

    val (success, _) = new Driver(ips, rt, ipt, "eth1") {
      override def initInstruction = InstructionBlock(
        Assign(Proto, ConstantValue(TCPProto)),
        Assign(IPSrc, ConstantValue(Ipv4(192, 168, 0, 120).host)),
        Assign(IPDst, ConstantValue(Ipv4(8, 8, 8, 8).host))
      )
    }.run()

    success should (
      have length (1) and
      containConstrain (
        Constrain(IPSrc, :&:(:>=:(ConstantValue(Ipv4(15, 15, 15, 15).host)),
                             :<=:(ConstantValue(Ipv4(15, 15, 15, 15).host))))
      ) and
      containConstrain (
        Constrain(TcpSrc, :&:(:>=:(ConstantValue(5000)),
                              :<=:(ConstantValue(10000))))
      )
    )
  }

  test("redirect nat") {
    val ips = """
      eth0 15.15.15.15
      eth1 192.168.0.1
    """
    val rt = """
      192.168.0.0/24 eth1
      0.0.0.0/0 eth0
    """
    val ipt = """
      <<nat>>
      <PREROUTING:ACCEPT>
        -d 8.8.8.8 -j REDIRECT
    """

    val driver = new Driver(ips, rt, ipt, "eth1") {
      override def initInstruction = InstructionBlock(
        Assign(IPDst, ConstantValue(Ipv4(8, 8, 8, 8).host))
      )
    }
    val (success, _) = driver.run()

    success should have length (1)
    success should reachPort (driver.iptRouter.localProcessInputPort)
    success(0) should containAssignment (
      IPDst,
      ConstantValue(Ipv4(192, 168, 0, 1).host)
    )
  }

  test("dnat'ed packet is not filtered") {
    val ips = """
      eth0 15.15.15.15
      eth1 192.168.0.1
    """
    val rt = """
      192.168.0.0/24 eth1
      0.0.0.0/0 eth0
    """
    val ipt = """
      <<nat>>
      <PREROUTING:ACCEPT>
        -d 15.15.15.15 -j DNAT --to-destination 192.168.0.10

      <<filter>>
      <FORWARD:DROP>
        ! -d 15.15.15.15 -j ACCEPT
    """

    {
      val driver = new Driver(ips, rt, ipt, "eth0") {
        override def initInstruction = InstructionBlock(
          Assign(IPDst, ConstantValue(Ipv4(15, 15, 15, 15).host))
        )
      }
      val (success, _) = driver.run()

      success should (
        have length (1) and
        reachPort (driver.iptRouter.outputPort("eth1"))
      )
    }
    {
      // Insert an unconstrained packet.
      val driver = new Driver(ips, rt, ipt, "eth0")
      val (success, _) = driver.run()

      success should (
        reachPort (driver.iptRouter.outputPort("eth1")) and
        reachPort (driver.iptRouter.outputPort("eth0")) and
        reachPort (driver.iptRouter.localProcessInputPort)
      )
    }
  }

  test("connection is established on reply") {
    val ips = """
      eth0 15.15.15.15
      eth1 192.168.0.1
    """
    val rt = """
      192.168.0.0/24 eth1
      0.0.0.0/0 eth0
    """
    val ipt = """
    """

    new SymnetFacade {
      override def deviceId = "simple-net"

      val driver = new Driver(ips, rt, ipt, "eth0")
      val iptRouter = driver.iptRouter

      val (success, _) = symExec(
        vds = List(iptRouter, ipMirror),
        initPort = iptRouter.outputPort("eth0"),
        otherInstr = InstructionBlock(
          Assign(IPSrc, ConstantValue(Ipv4(15, 15, 15, 15).host)),
          Assign(IPDst, ConstantValue(Ipv4(8, 8, 8, 8).host)),

          Assign(driver.ctstate, ConstantValue(ConnectionState.New.id))
        ),
        otherLinks = Map(
          iptRouter.outputPort("eth0") -> ipMirror.inputPort(0),
          ipMirror.outputPort(0) -> iptRouter.inputPort("eth0")
        ),
        log = true
      )

      success should (
        have length (1) and
        reachPort (iptRouter.localProcessInputPort)
      )
      success(0) should containAssignment (
        driver.ctstate,
        ConstantValue(ConnectionState.Established.id)
      )
    }
  }
}
