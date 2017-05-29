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
import org.change.v2.analysis.expression.concrete._
import org.change.v2.analysis.processingmodels.instructions._
import org.change.v2.util.canonicalnames._

// project
// -> core
import core._

// -> types
import types.net.Ipv4

@RunWith(classOf[JUnitRunner])
class ContiguousIVDSuite
  extends FunSuite with SymnetMisc
                   with Inside
                   with Matchers
                   with SymnetCustomMatchers { self =>
  import VirtdevSuitesCommon._

  override def deviceId: String = "ipt-router"

  private def buildIt(rs: Rule*) =
    ContiguousIVD("contig-ivd", new ContiguousIVDConfig {
      val deviceId = self.deviceId
      val portsMap = VirtdevSuitesCommon.portsMap
      val rules = rs.toList
    })

  private def buildIt(name: String, rs: Rule*) =
    ContiguousIVD(name, new ContiguousIVDConfig {
      val deviceId = self.deviceId
      val portsMap = VirtdevSuitesCommon.portsMap
      val rules = rs.toList
    })

  ///
  /// Simple tests
  ///
  test("empty rules, default instruction") {
    val contig = buildIt()

    contig.links shouldBe empty
    contig.portInstructions should not be empty

    val inputInstr = contig.portInstructions(contig.inputPort)
    inputInstr shouldBe Forward(contig.nextIVDport)
  }

  test("one rule, match TCP proto") {
    val contig = buildIt(
      toRule("-p tcp -j ACCEPT")
    )

    contig.links shouldBe empty
    contig.portInstructions should not be empty

    val (success, fail) = symExec(contig, contig.inputPort)
    assert(success.length == 2) // 1 if => 2 paths
    assert(fail.isEmpty)
  }

  test("one rule, match negated src ip") {
    val contig = buildIt(
      toRule("-s ! 192.168.0.1 -j ACCEPT")
    )
    val ip = ConstantValue(Ipv4(192, 168, 0, 1).host)

    val (success, fail) = symExec(contig, contig.inputPort)
    success should (
      have length (2) and
      containPath (contig.inputPort, contig.acceptPort) and
      containPath (contig.inputPort, contig.nextIVDport)
    )
    fail shouldBe empty
  }

  test("one rule, match interface and ip and then return") {
    val contig = buildIt(
      toRule("-i eth0 -d 10.10.10.0/24 -j RETURN")
    )
    val (lo, up) = Ipv4(10, 10, 10, 0, Some(24)).toHostRange
    val (loIp, upIp) = (ConstantValue(lo.host), ConstantValue(up.host))

    // If the input port tag is set to a symbolic value, we have 3 possible
    // paths.
    {
      val (success, fail) =
        symExec(
          contig,
          contig.inputPort,
          Assign(InputPortTag, SymbolicValue())
        )
      success should (
        have length (3) and
        containPath (contig.inputPort, contig.returnPort) and
        containPath (contig.inputPort, contig.nextIVDport)
      )
      fail shouldBe empty
    }

    // If the input port tag is set to a constant value equal to the matched
    // input interface, we have 2 success paths and 1 failure path
    {
      val (success, fail) =
        symExec(
          contig,
          contig.inputPort,
          Assign(InputPortTag, ConstantValue(portsMap("eth0")))
        )

      success should (
        have length (2) and
        containPath (contig.inputPort, contig.returnPort) and
        containPath (contig.inputPort, contig.nextIVDport)
      )
      fail should (
        have length (1) and
        containPath (contig.inputPort)
      )
    }

    // If the input port tag is set to a constant value other than the matched
    // one, we have one success path, to the `else' branch, and one failure
    // path ('Symbol `input-port' cannot be equal to `eth1'').
    {
      val (success, fail) =
        symExec(
          contig,
          contig.inputPort,
          Assign(InputPortTag, ConstantValue(portsMap("eth1")))
        )
      success should (
        have length (1) and
        containPath (contig.inputPort, contig.nextIVDport)
      )
      fail should (
        have length (1) and
        containPath (contig.inputPort)
      )
    }
  }

  test("second rule is not reachable") {
    val contig = buildIt(
      toRule("-s 192.168.0.0/24 -j DROP"),
      toRule("-s 192.168.0.5 -j ACCEPT")
    )
    val (success, fail) = symExec(contig, contig.inputPort)

    success should not (reachPort (contig.acceptPort))
    fail should reachPort (contig.dropPort)
  }

  test("rl lecture - unreachable example") {
    val postChain = buildIt(
      toRule("-s 192.168.1.0/24 -j SNAT --to-source 141.85.200.2-141.85.200.6"),
      toRule("-s 192.168.1.100 -j SNAT --to-source 141.85.200.1")
    )
    val rewriteConstrain1 =
      Constrain(IPSrc, :&:(:>=:(ConstantValue(Ipv4(141, 85, 200, 2).host)),
                           :<=:(ConstantValue(Ipv4(141, 85, 200, 6).host))))
    val rewriteConstrain2 =
      Constrain(IPSrc, :&:(:>=:(ConstantValue(Ipv4(141, 85, 200, 1).host)),
                           :<=:(ConstantValue(Ipv4(141, 85, 200, 1).host))))

    val (success, _) =
      symExec(
        postChain,
        postChain.inputPort,
        Assign(IPSrc, ConstantValue(Ipv4(192, 168, 1, 100).host))
      )

    success should (
      // Well, this is not what we expected :(...
      not (containConstrain (rewriteConstrain2)) and

      // It does match the first one, though
      containConstrain (rewriteConstrain1)
    )
  }

  test("one rule, source nat") {
    val contig = buildIt(
      toRule("-s 192.168.2.0/24 -j SNAT --to-source 15.15.15.15-15.15.15.138")
    )
    val inputInstr = contig.portInstructions(contig.inputPort)
    val rewriteConstrain =
      Constrain(IPSrc, :&:(:>=:(ConstantValue(Ipv4(15, 15, 15, 15).host)),
                           :<=:(ConstantValue(Ipv4(15, 15, 15, 138).host))))

    // If the source matches (i.e. its symbolic by default), or, more precisely,
    // *could* match, then there must be a path in which it gets rewritten ...
    {
      val (success, _) = symExec(contig, contig.inputPort)
      success should containConstrain (rewriteConstrain)
    }

    // ... otherwise, it shouldn't.
    {
      val (success, _) =
        symExec(
          contig,
          contig.inputPort,
          Assign(IPSrc, ConstantValue(Ipv4(192, 168, 3, 20).host))
        )
      success should not (containConstrain (rewriteConstrain))
    }
  }

  test("one rule, destination nat") {
    val preroutingNat = buildIt(
      toRule("-d 2.5.2.0/24 -j DNAT --to-destination 192.168.2.5-192.168.2.100")
    )
    val inputInstr = preroutingNat.portInstructions(preroutingNat.inputPort)
    val rewriteConstrain =
      Constrain(IPDst, :&:(:>=:(ConstantValue(Ipv4(192, 168, 2, 5).host)),
                           :<=:(ConstantValue(Ipv4(192, 168, 2, 100).host))))

    // If the destination matches (i.e. its symbolic by default), or, more
    // precisely, *could* match, then there must be a path in which it gets
    // rewritten ...
    {
      val (success, _) = symExec(preroutingNat, preroutingNat.inputPort)
      success should containConstrain (rewriteConstrain)
    }

    // ... otherwise, it shouldn't.
    {
      val (success, _) =
        symExec(
          preroutingNat,
          preroutingNat.inputPort,
          Assign(IPDst, ConstantValue(Ipv4(2, 5, 3, 100).host))
        )
      success should not (containConstrain (rewriteConstrain))
    }
  }

  test("jump to user chain") {
    // NOTE: We have to call `validate' here to ensure that the jump is
    // correctly set up as part of the target, as the user-defined chain comes
    // after the jump.
    val filterTable = toTable("""
      <<filter>>
        <FORWARD:DROP>
          -i eth0 -j MY_CHAIN
        <MY_CHAIN>
          -s 192.168.1.0/30 -j RETURN
    """)

    val forwardRules = filterTable.chains.collect {
      case BuiltinChain("FORWARD", rules, _) => rules
    }.flatten
    val myRules = filterTable.chains.collect {
      case UserChain("MY_CHAIN", rules) => rules
    }.flatten

    // Sanity checks.
    forwardRules should have length (1)
    myRules should have length (1)

    // Create a contiguous IVD from each one of them.
    {
      val contig = buildIt(forwardRules: _*)
      val (success, _) =
        symExec(
          contig,
          contig.inputPort,
          Assign(InputPortTag, ConstantValue(portsMap("eth0")))
        )

      success should reachPort (contig.jumpPort)
    }

    {
      val contig = buildIt(myRules: _*)
      val (success, _) = symExec(contig, contig.inputPort)

      success should reachPort (contig.returnPort)
    }
  }

  ///
  /// TCP/UDP codegen extension suite.
  ///

  test("tcp/udp port match") {
    val contig = buildIt(
      toRule("-m tcp --sport 80 -j ACCEPT")
    )

    val (success, _) =
      symExec(contig, contig.inputPort, Assign(TcpSrc, ConstantValue(80)))

    success should (
      reachPort(contig.acceptPort) and
      containConstrain (Constrain(TcpSrc, :&:(:>=:(ConstantValue(80)),
                                              :<=:(ConstantValue(80)))))
    )
  }

  test("tcp destination port match") {
    val contig = buildIt(
      toRule("-p tcp --dport 80 -j ACCEPT")
    )

    val (success, _) =
      symExec(contig, contig.inputPort, Assign(TcpDst, ConstantValue(80)))

    success should (
      reachPort (contig.acceptPort) and
      containConstrain (Constrain(TcpDst, :&:(:>=:(ConstantValue(80)),
                                              :<=:(ConstantValue(80)))))
    )
  }

  test("tcp syn flag match") {
    val contig = buildIt(
      toRule("-p tcp --syn -j ACCEPT")
    )

    val (success, fail) =
      symExec(
        contig,
        contig.inputPort,
        InstructionBlock(
          Assign(TcpFlagSYN, ConstantValue(1)),
          Assign(TcpFlagRST, ConstantValue(0)),
          Assign(TcpFlagACK, ConstantValue(0)),
          Assign(TcpFlagFIN, ConstantValue(0))
        )
      )

    success should reachPort (contig.acceptPort)
    fail should not (reachPort (contig.dropPort))
  }

  test("tcp flags match") {
    val contig = buildIt(
      toRule("-p tcp --tcp-flags SYN,ACK ALL -j ACCEPT")
    )

    {
      val (success, fail) =
        symExec(
          contig,
          contig.inputPort,
          InstructionBlock(
            Assign(TcpFlagSYN, ConstantValue(1)),
            Assign(TcpFlagACK, ConstantValue(0))
          )
        )

      success should not (reachPort (contig.acceptPort))
    }
    {
      val (success, fail) =
        symExec(
          contig,
          contig.inputPort,
          InstructionBlock(
            Assign(TcpFlagSYN, ConstantValue(1)),
            Assign(TcpFlagACK, ConstantValue(1))
          )
        )

      success should reachPort (contig.acceptPort)
    }
  }

  test("negated tcp flags match") {
    val contig = buildIt(
      toRule("-p tcp ! --tcp-flags SYN,ACK ALL -j ACCEPT")
    )

    val (success, fail) =
      symExec(
        contig,
        contig.inputPort,
        InstructionBlock(
          Assign(TcpFlagSYN, ConstantValue(1)),
          Assign(TcpFlagACK, ConstantValue(1))
        )
      )

    success should not (reachPort (contig.acceptPort))
  }

  test("mark target") {
    val mangleTable = toTable("""
      <<mangle>>
        <PREROUTING:ACCEPT>
          -i eth+ -j MARK --set-xmark 0x2/0xffff
    """)
    val contig = buildIt(mangleTable.chains(0).rules: _*)

    val (success, fail) =
      symExec(
        contig,
        contig.inputPort,
        Assign(InputPortTag, ConstantValue(portsMap("eth0")))
      )

    // NOTE: The `nextIVDPort' should be linked to the accept port of the outer
    // ipt router.
    // TODO: Add a separate test to prove this.
    success should reachPort (contig.nextIVDport)
    dropped(fail, contig) shouldBe empty
  }

  test("mark match") {
    val filterTable = toTable("""
      <<filter>>
        <FORWARD:DROP>
          -m mark --mark 0x2/0xffff -j ACCEPT
    """)
    val contig = buildIt(filterTable.chains(0).rules: _*)

    val (success, fail) =
      symExec(
        contig,
        contig.inputPort,
        // NOTE: It matches the mark from above.
        Assign(nfmark, ConstantBitVector(0x0002))
      )

    success should reachPort (contig.acceptPort)
    dropped(fail, contig) shouldBe empty
  }

  test("mark match negated") {
    val filterTable = toTable("""
      <<filter>>
        <FORWARD:DROP>
          -m mark --mark 0x2/0xffff -j ACCEPT
    """)
    val contig = buildIt(filterTable.chains(0).rules: _*)

    val (success, _) =
      symExec(
        contig,
        contig.inputPort,
        // NOTE: It doesn't match the mark from above.
        Assign(nfmark, ConstantBitVector(0x0001))
      )

    accepted(success, contig) shouldBe empty
    success should reachPort (contig.nextIVDport)
  }

  test("connmark match and target") {
    // The only rule in the PREROUTING chain from the mangle table says that if
    // the ctmark value does not have the most significant 2 bytes set to 0,
    // then xor them into Nfmark.
    val mangleTable = toTable("""
      <<mangle>>
      <PREROUTING:ACCEPT>
        -m connmark ! --mark 0x0/0xffff0000
          -j CONNMARK --restore-mark --nfmask 0xffff0000 --ctmask 0xffff0000
    """)
    val filterTable = toTable("""
      <<filter>>
      <FORWARD:DROP>
        -m mark --mark 0xDEAD0000/0xffff0000 -j ACCEPT
    """)

    val mangleContig = buildIt("mangle-ivd", mangleTable.chains(0).rules: _*)
    val filterContig = buildIt("filter-ivd", filterTable.chains(0).rules: _*)

    val (success, fail) =
      symExec(
        vds = List(mangleContig, filterContig),
        initPort = mangleContig.inputPort,
        otherInstr = InstructionBlock(
          Assign(ctmark, ConstantBitVector(0xDEADBEEF)),
          Assign(nfmark, ConstantBitVector(0x00001234))
        ),
        otherLinks = Map(mangleContig.acceptPort -> filterContig.inputPort),
        log = false
      )

    accepted(success, filterContig) should have length (1)
  }
}
