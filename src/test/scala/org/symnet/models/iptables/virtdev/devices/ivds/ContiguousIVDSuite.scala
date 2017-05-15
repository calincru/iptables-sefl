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
import org.change.v2.analysis.processingmodels.instructions._
import org.change.v2.util.canonicalnames._

// project
// -> core
import core._

// -> types
import types.net.Ipv4

@RunWith(classOf[JUnitRunner])
class ContiguousIVDSuite
  extends FunSuite with Inside
                   with Matchers
                   with SymnetCustomMatchers { self =>
  import VirtdevSuitesCommon._

  private def buildIt(rs: Rule*) =
    ContiguousIVD("contig-ivd", new ContiguousIVDConfig {
      val id = "ipt-router"
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

    val inputInstr = contig.portInstructions(contig.inputPort)
    inputInstr shouldBe
      If(Constrain(Proto, :==:(ConstantValue(TCPProto))),
         Forward(contig.acceptPort),
         Forward(contig.nextIVDport))

    val (success, fail) = SymnetMisc.symExec(contig, contig.inputPort)
    assert(success.length == 2) // 1 if => 2 paths
    assert(fail.isEmpty)
  }

  test("one rule, match src ip") {
    val contig = buildIt(
      toRule("-s 192.168.0.1 -j ACCEPT")
    )
    val ip = ConstantValue(Ipv4(192, 168, 0, 1).host)

    val inputInstr = contig.portInstructions(contig.inputPort)
    inputInstr shouldBe
      If(Constrain(IPSrc, :&:(:>=:(ip), :<=:(ip))),
         Forward(contig.acceptPort),
         Forward(contig.nextIVDport))

    val (success, fail) = SymnetMisc.symExec(contig, contig.inputPort)
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

    val inputInstr = contig.portInstructions(contig.inputPort)
    inputInstr shouldBe
      If(Constrain(InputPortTag, :==:(ConstantValue(portsMap("eth0")))),
         If(Constrain(IPDst, :&:(:>=:(loIp), :<=:(upIp))),
            Forward(contig.returnPort),
            Forward(contig.nextIVDport)),
         Forward(contig.nextIVDport))

    // If the input port tag is set to a symbolic value, we have 3 possible
    // paths.
    {
      val (success, fail) =
        SymnetMisc.symExec(
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
        SymnetMisc.symExec(
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
        SymnetMisc.symExec(
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

  test("two rules, drop/accept") {
    val contig = buildIt(
      toRule("-o eth1 -p udp -s 172.16.0.171 -j DROP"),
      toRule("-i eth2 -p all -j ACCEPT")
    )
    val ip = ConstantValue(Ipv4(172, 16, 0, 171).host)
    val secondInstr =
      // NOTE: '-p all' doesn't add any constraints.
      If(Constrain(InputPortTag, :==:(ConstantValue(portsMap("eth2")))),
         // matched
         Forward(contig.acceptPort),
         // default instr
         Forward(contig.nextIVDport))
    val firstInstr =
      If(Constrain(OutputPortTag, :==:(ConstantValue(portsMap("eth1")))),
         // and ...
         If(Constrain(Proto, :==:(ConstantValue(UDPProto))),
            // and ...
            If(Constrain(IPSrc, :&:(:>=:(ip), :<=:(ip))),
               // matched
               Forward(contig.dropPort),
               // else
               secondInstr),
            // else
            secondInstr),
         // else
         secondInstr)

    contig.portInstructions(contig.inputPort) shouldBe firstInstr
  }

  test("second rule is not reachable") {
    val contig = buildIt(
      toRule("-s 192.168.0.0/24 -j DROP"),
      toRule("-s 192.168.0.5 -j ACCEPT")
    )
    val (success, fail) = SymnetMisc.symExec(contig, contig.inputPort)

    success should not (reachPort (contig.acceptPort))
    fail should reachPort (contig.dropPort)
  }

  test("rl lecture - unreachable example") {
    val contig = buildIt(
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
      SymnetMisc.symExec(
        contig,
        contig.inputPort,
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

    inside (inputInstr) { case If(testInstr, thenInstr, elseInstr) =>
      inside (testInstr) { case ConstrainRaw(what, withWhat, _) =>
        what shouldBe IPSrc
        withWhat shouldBe :&:(:>=:(ConstantValue(Ipv4(192, 168, 2, 0).host)),
                              :<=:(ConstantValue(Ipv4(192, 168, 2, 255).host)))
      }
      inside (thenInstr) { case InstructionBlock(instrs) =>
        // This ensures NAT correctly rewrites the source address.
        instrs should contain allOf (
          Assign(IPSrc, SymbolicValue()),
          rewriteConstrain
        )
      }
      elseInstr shouldBe Forward(contig.nextIVDport)
    }

    // If the source matches (i.e. its symbolic by default), or, more precisely,
    // *could* match, then there must be a path in which it gets rewritten ...
    {
      val (success, _) = SymnetMisc.symExec(contig, contig.inputPort)
      success should containConstrain (rewriteConstrain)
    }

    // ... otherwise, it shouldn't.
    {
      val (success, _) =
        SymnetMisc.symExec(
          contig,
          contig.inputPort,
          Assign(IPSrc, ConstantValue(Ipv4(192, 168, 3, 20).host))
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
      val inputInstr = contig.portInstructions(contig.inputPort)

      // The thing we are testing here is that the jump on the `then' branch
      // should go to the jump port.
      inputInstr shouldBe
        If(Constrain(InputPortTag, :==:(ConstantValue(portsMap("eth0")))),
           Forward(contig.jumpPort),
           Forward(contig.nextIVDport))
    }

    {
      val contig = buildIt(myRules: _*)
      val inputInstr = contig.portInstructions(contig.inputPort)

      inputInstr shouldBe
        If(Constrain(IPSrc, :&:(:>=:(ConstantValue(Ipv4(192, 168, 1, 0).host)),
                                :<=:(ConstantValue(Ipv4(192, 168, 1, 3).host)))),
           Forward(contig.returnPort),
           Forward(contig.nextIVDport))
    }
  }
}
