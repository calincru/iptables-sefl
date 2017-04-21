// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet
package models.iptables
package virtdev.devices.ivds

// scala
import org.junit.runner.RunWith
import org.scalatest.{FunSuite, Matchers}
import org.scalatest.junit.JUnitRunner

// 3rd party:
// -> Symnet
import org.change.v2.analysis.expression.concrete.ConstantValue
import org.change.v2.analysis.memory.State
import org.change.v2.analysis.processingmodels.Instruction
import org.change.v2.analysis.processingmodels.instructions._
import org.change.v2.executor.clickabstractnetwork.ClickExecutionContext
import org.change.v2.executor.clickabstractnetwork.executionlogging.JsonLogger
import org.change.v2.util.canonicalnames._

// project
// -> core
import core._
import core.iptParsers.ruleParser

// -> types
import types.net.Ipv4

// -> filter
import extensions.filter.FilteringExtension

// -> virtdev
import virtdev.NetworkModel

@RunWith(classOf[JUnitRunner])
class ContiguousIVDSuite extends FunSuite with Matchers { self =>

  private val portsMap = Map("eth0" -> 0, "eth1" -> 1, "eth2" -> 2)

  private def symExec(contIVD: ContiguousIVD) = {
    val model = NetworkModel(contIVD)
    val result = new ClickExecutionContext(
      model.instructions,
      model.links,
      List(State.bigBang.forwardTo(contIVD.inputPort)),
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

  private implicit def ParsingContext = new ParsingContext {
    override val matchExtensions  =
      List(FilteringExtension)
    override val targetExtensions =
      List(FilteringExtension, ChainTargetExtension)
  }

  private def rule(ruleStr: String) = ruleParser.eval(ruleStr).toOption.get

  ///
  /// Simple tests
  ///

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
    // TODO: Do something with this.
  }

  test("one rule, match src ip") {
    val contig = buildIt(
      rule("-s 192.168.0.1 -j ACCEPT")
    )
    val ip = ConstantValue(Ipv4(192, 168, 0, 1).host)

    assert(contig.links.isEmpty)
    assert(!contig.portInstructions.isEmpty)

    val inputInstr = contig.portInstructions(contig.inputPort)
    inputInstr shouldBe
      If(Constrain(IPSrc, :&:(:>=:(ip), :<=:(ip))),
         Forward(contig.acceptPort),
         Forward(contig.nextIVDport))

    val (success, fail) = symExec(contig)
    // TODO: Do something with this.
  }
}
