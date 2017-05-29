// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet
package models.iptables
package virtdev
package devices.ivds

// scala
import org.junit.runner.RunWith
import org.scalatest.{FunSuite, Inside, Matchers}
import org.scalatest.junit.JUnitRunner

// 3rd party:
// -> Symnet
import org.change.v2.analysis.expression.concrete.{ConstantValue, SymbolicValue}
import org.change.v2.analysis.memory.State
import org.change.v2.analysis.processingmodels.instructions._
import org.change.v2.util.canonicalnames._

// project
// -> core
import core._

// -> types
import types.net.Ipv4

// -> devices
import devices.IPTIndex

// TODO: Multiple tests in this suite assume that the chain traversal is
// implemented as a big If/Then/Else statement.
@RunWith(classOf[JUnitRunner])
class ChainIVDSuite
  extends FunSuite with SymnetFacade
                   with Inside
                   with Matchers
                   with SymnetCustomMatchers { self =>
  import VirtdevSuitesCommon._

  override def deviceId: String = "ivd"

  private def buildIt(table: Table, neighs: List[Int] = Nil) = {
    val chain = table.chains.head
    val rules = new IPTIndex(List(table)).chainsSplitSubrules(chain)
    val idx = if (neighs.isEmpty) 0 else neighs.max + 1

    new ChainIVDBuilder(
      deviceId, chain, table, idx, rules, neighs, portsMap, deviceId).build
  }

  test("empty chain, packet gets dropped") {
    val filterTable = toTable("""
      <<filter>>
      <FORWARD:DROP>
    """)
    val ivd = buildIt(filterTable)

    ivd.links should contain key ivd.inputPort
    ivd.links should contain key ivd.inputPort

    val (success, fail) = symExec(ivd, ivd.inputPort)

    success shouldBe empty
    dropped(fail, ivd) should (
      have length (1) and
      passThrough (ivd.inputPort, ivd.dropPort)
    )
  }

  test("empty chain with default accept") {
    val preroutingTable = toTable("""
      <<nat>>
      <PREROUTING:ACCEPT>
    """)
    val ivd = buildIt(preroutingTable)
    val (success, fail) = symExec(ivd, ivd.inputPort)

    dropped(fail, ivd) shouldBe empty
    success should (
      have length (1) and
      passThrough (ivd.inputPort, ivd.acceptPort)
    )
  }

  test("one rule, one accepted, one dropped, one failed") {
    val filterTable = toTable("""
      <<filter>>
      <FORWARD:DROP>
        -i eth0 -j ACCEPT
    """)
    val ivd = buildIt(filterTable)
    val (success, fail) =
      symExec(ivd, ivd.inputPort, Assign(InputPortTag, SymbolicValue()))

    dropped(fail, ivd) should (
      have length (1) and

      // One path should fail because it considers an input port other than
      // 'eth0' which fails (is dropped) due to the default policy.
      passThrough (ivd.inputPort, ivd.dropPort)
    )
    success should (
      // There is only one path that gets accepted.
      have length (1) and
      passThrough (ivd.inputPort, ivd.returnInputPort, ivd.acceptPort)
    )
  }

  test("two rules, same chain") {
    val filterTable = toTable("""
      <<filter>>
      <FORWARD:DROP>
        -s 192.168.0.2/24 -j ACCEPT
        -s 172.16.0.2/18 -j ACCEPT
    """)
    val ivd = buildIt(filterTable)
    val cstr1 = :&:(:>=:(ConstantValue(Ipv4(192, 168, 0, 0).host)),
                    :<=:(ConstantValue(Ipv4(192, 168, 0, 255).host)))
    val cstr2 = :&:(:>=:(ConstantValue(Ipv4(172, 16, 0, 0).host)),
                    :<=:(ConstantValue(Ipv4(172, 16, 63, 255).host)))
    val (success, fail) = symExec(ivd, ivd.inputPort)

    success should (
      have length (2) and
      containConstrain (Constrain(IPSrc, cstr1)) and
      containConstrain (Constrain(IPSrc, cstr2))
    )
    dropped(fail, ivd) should (
      have length (1) and
      containConstrain (Constrain(IPSrc, :~:(cstr1))) and
      containConstrain (Constrain(IPSrc, :~:(cstr2)))
    )
  }

  // NOTE: ChainIVDs linking suite is implemented in UserChainsLinker suite.
  test("two rules, one to user chain") {
    val filterTable = toTable("""
      <<filter>>
      <FORWARD:DROP>
        -p tcp -j MY_CHAIN
      <MY_CHAIN>
        -i eth0 -j ACCEPT
    """)
    val ivd = buildIt(filterTable)
    val protoCstr = :==:(ConstantValue(TCPProto))

    val (success, fail) =
      symExec(ivd, ivd.inputPort, Assign(InputPortTag, SymbolicValue()))

    success should (
      // The only 'successful' state is the one which matches protocol TCP and
      // *would* jump to the user-defined chain.
      have length (1) and
      reachPort (ivd.jumpPort(0)) and

      // ACCEPT port is not reached as the jump/return ports are not linked
      // together yet.
      not (reachPort (ivd.acceptPort)) and
      containConstrain (Constrain(Proto, protoCstr))
    )
    dropped(fail, ivd) should (
      have length (1) and
      containConstrain (Constrain(Proto, :~:(protoCstr)))
    )
  }

  test("user-chain return") {
    val filterTable = toTable("""
      <<filter>>
      <MY_CHAIN>
        -d 8.8.8.8 -j RETURN
    """)
    // NOTE: It's important to specify the ids of the chains which might jump to
    // this one, to adjust the number of backlink ports accordingly.
    val ivd = buildIt(filterTable, List(5))
    val ip = Ipv4(8, 8, 8, 8).host
    val cstr = :&:(:>=:(ConstantValue(ip)), :<=:(ConstantValue(ip)))

    val (success, fail) =
      symExec(
        ivd,
        ivd.inputPort,

        // It's important to set this because in order to execute a 'RETURN' we
        // should have jumped from somewhere else (and that's where this is
        // set in the real code). See next test.
        //
        // NOTE: It matches the `5' from above.
        Assign(OutputDispatchTag, ConstantValue(5))
      )

    success should (
      // 1. one matches `-d 8.8.8.8' and RETURNs
      // 2. the other one doesn't match it and (still) RETURNs (default policy)
      have length (2) and

      // 1.
      containConstrain (Constrain(IPDst, :~:(cstr))) and

      // 2.
      containConstrain (Constrain(IPDst, cstr)) and

      // Both.
      reachPort (ivd.backlinkPort(0)) and
      passThrough (ivd.inputPort, ivd.backlinkPort(0))
    )

    // No packet should be dropped as far as this chain is concerned.
    dropped(fail, ivd) shouldBe empty
  }

  test("return without OutputDispatchTag set fails") {
    val filterTable = toTable("""
      <<filter>>
      <MY_CHAIN>
        -d 8.8.8.8 -j RETURN
    """)
    val ivd = buildIt(filterTable, List(5))
    val (success, _) = symExec(ivd, ivd.inputPort)

    success shouldBe empty
  }

  test("multiple jumps to user-defined chains") {
    val filterTable = toTable("""
      <<filter>>
      <FORWARD:DROP>
        -p tcp -j CHAIN0
        -p udp -j CHAIN1
        -p icmp -j CHAIN2
        -p all -j ACCEPT
      <CHAIN0>
      <CHAIN1>
      <CHAIN2>
    """)
    val ivd = buildIt(filterTable)
    val (success, fail) = symExec(ivd, ivd.inputPort)
    val toConstrain = (proto: Int) => :==:(ConstantValue(proto))

    success should (
      have length (4) and

      // Reach 3 different jump ports.
      reachPort (ivd.jumpPort(0)) and
      reachPort (ivd.jumpPort(1)) and
      reachPort (ivd.jumpPort(2)) and

      // Reach the accept port, with the contraint that it doesn't match any of
      // the given input interfaces.
      reachPort (ivd.acceptPort) and
      containConstrain (Constrain(Proto, :~:(toConstrain(TCPProto)))) and
      containConstrain (Constrain(Proto, :~:(toConstrain(UDPProto)))) and
      containConstrain (Constrain(Proto, :~:(toConstrain(ICMPProto))))
    )
  }

  test("return in built-in chain should apply chain policy") {
    val filterTable = toTable("""
      <<filter>>
      <FORWARD:ACCEPT>
        -p all -j RETURN
    """)
    val ivd = buildIt(filterTable)
    val (success, fail) = symExec(ivd, ivd.inputPort)

    dropped(fail, ivd) shouldBe empty
    success should have length (1)
  }

  test("nat'ed packet is skiped") {
    // TODO: Add this.
  }
}
