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
import core.iptParsers.{chainParser, ruleParser, tableParser}

// -> types
import types.net.Ipv4

@RunWith(classOf[JUnitRunner])
class ChainIVDSuite
  extends FunSuite with Inside
                   with Matchers
                   with SymnetCustomMatchers { self =>
  import VirtdevSuitesCommon._

  private def buildIt(
      chain: Chain,
      table: Table,
      rules: List[List[Rule]],
      neighbourChainIndices: List[Int]) =
    new ChainIVDBuilder(
      "chain0", // name
      chain,
      table,
      0, // index
      rules,
      neighbourChainIndices,
      portsMap
    ).build

  test("empty chain") {
    val filterTable = toTable("""
      <<filter>>
      <FORWARD:DROP>
    """)
    val ivd = buildIt(filterTable.chains.head, filterTable, Nil, Nil)

    ivd.links should contain key ivd.initPort
    ivd.links should contain key ivd.inputPort

    val (success, fail) = SymnetMisc.symExec(ivd, ivd.initPort)

    success shouldBe empty
    fail should (
      have length (1)
      // TODO: Add a matcher to check only parts of the port trace of a packet.
    )
  }
}
