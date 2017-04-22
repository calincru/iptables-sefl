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
import org.change.v2.executor.clickabstractnetwork.ClickExecutionContext
import org.change.v2.executor.clickabstractnetwork.executionlogging.JsonLogger
import org.change.v2.util.canonicalnames._

// project
// -> core
import core._
import core.iptParsers.{ruleParser, tableParser}

// -> types
import types.net.Ipv4

// -> extensions
import extensions.filter.FilteringExtension
import extensions.nat.SnatTargetExtension

// -> virtdev
import virtdev.{InputPortTag, OutputIpTag}
import virtdev.NetworkModel

@RunWith(classOf[JUnitRunner])
class ContiguousIVDSuite
  extends FunSuite with Inside
                   with Matchers
                   with SymnetCustomMatchers { self =>

  private val portsMap = Map("eth0" -> 0, "eth1" -> 1, "eth2" -> 2)

  private def symExec(contIVD: ContiguousIVD, otherInstr: Instruction = NoOp) = {
    val model = NetworkModel(contIVD)
    val result = new ClickExecutionContext(
      model.instructions,
      model.links,
      List(SymnetMisc.initState(otherInstr).forwardTo(contIVD.inputPort)),
      Nil,
      Nil,
      logger = JsonLogger).untilDone(true)

    (result.stuckStates, result.failedStates)
  }

  private def buildIt(rs: Rule*) =
    ContiguousIVD("contig-ivd", new ContiguousIVDConfig {
      val id = "ipt-router"
      val portsMap = self.portsMap
      val rules = rs.toList
    })

  private implicit def parsingContext = new ParsingContext {
    override val matchExtensions  =
      List(FilteringExtension)
    override val targetExtensions =
      List(SnatTargetExtension,
           FilteringExtension,
           ChainTargetExtension)
  }

  private def rule(ruleStr: String) = ruleParser.eval(ruleStr).toOption.get

  ///
  /// Simple tests
  ///
  test("empty rules, default instruction") {
    val contig = buildIt()

    assert(contig.links.isEmpty)
    assert(!contig.portInstructions.isEmpty)

    val inputInstr = contig.portInstructions(contig.inputPort)
    inputInstr shouldBe Forward(contig.nextIVDport)
  }

  test("one rule, match TCP proto") {
    val contig = buildIt(
      rule("-p tcp -j ACCEPT")
    )

    assert(contig.links.isEmpty)
    assert(!contig.portInstructions.isEmpty)

    val inputInstr = contig.portInstructions(contig.inputPort)
    inputInstr shouldBe
      If(Constrain(Proto, :==:(ConstantValue(TCPProto))),
         Forward(contig.acceptPort),
         Forward(contig.nextIVDport))

    val (success, fail) = symExec(contig)
    assert(success.length == 2) // 1 if => 2 paths
    assert(fail.isEmpty)
  }

  test("one rule, match src ip") {
    val contig = buildIt(
      rule("-s 192.168.0.1 -j ACCEPT")
    )
    val ip = ConstantValue(Ipv4(192, 168, 0, 1).host)

    val inputInstr = contig.portInstructions(contig.inputPort)
    inputInstr shouldBe
      If(Constrain(IPSrc, :&:(:>=:(ip), :<=:(ip))),
         Forward(contig.acceptPort),
         Forward(contig.nextIVDport))

    val (success, fail) = symExec(contig)
    success should (
      have length (2) and
      containPath (contig.inputPort, contig.acceptPort) and
      containPath (contig.inputPort, contig.nextIVDport)
    )
    fail shouldBe empty
  }

  test("one rule, match interface and ip and then return") {
    val contig = buildIt(
      rule("-i eth0 -d 10.10.10.0/24 -j RETURN")
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
        symExec(contig, Assign(InputPortTag, SymbolicValue()))
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
        symExec(contig, Assign(InputPortTag, ConstantValue(portsMap("eth0"))))
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
        symExec(contig, Assign(InputPortTag, ConstantValue(portsMap("eth1"))))
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
      rule("-o eth1 -p udp -s 172.16.0.171 -j DROP"),
      rule("-i eth2 -p all -j ACCEPT")
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

  test("one rule, source nat") {
    val contig = buildIt(
      rule("-s 192.168.2.0/24 -j SNAT --to-source 15.15.15.15-15.15.15.138")
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
      val (success, fail) = symExec(contig)
      success should containConstrain (rewriteConstrain)
    }

    // ... otherwise, it shouldn't.
    {
      val (success, fail) =
        symExec(contig, Assign(IPSrc, ConstantValue(Ipv4(192, 168, 3, 20).host)))
      success should not (containConstrain (rewriteConstrain))
    }
  }

  test("jump to user chain") {
    // NOTE: We have to call `validate' here to ensure that the jump is
    // correctly set up as part of the target, as the user-defined chain comes
    // after the jump.
    val filterTable = tableParser.eval("""
      <<filter>>
        <FORWARD:DROP>
          -i eth0 -j MY_CHAIN
        <MY_CHAIN>
          -s 192.168.1.0/30 -j RETURN
    """).flatMap(_.validate).toOption.get

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
