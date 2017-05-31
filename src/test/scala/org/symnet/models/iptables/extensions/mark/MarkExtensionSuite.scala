// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet
package models.iptables
package extensions.mark

// scala
import org.junit.runner.RunWith
import org.scalatest.{FunSuite, Matchers}
import org.scalatest.junit.JUnitRunner

// 3rd party:
// -> scalaz
import scalaz.Maybe._

// project
import core._
import core.iptParsers.{ruleParser, tableParser}
import extensions.filter._

@RunWith(classOf[JUnitRunner])
class MarkExtensionSuite extends FunSuite with Matchers
                                          with ValidationCustomMatchers {

  implicit private val context = ParsingContext(
    List(FilteringExtension, MarkModuleLoader),
    List(FilteringExtension, MarkTargetExtension)
  )

  test("parsing mark match") {
    ruleParser.apply("-m mark --mark 0x2/0xffff -j ACCEPT") should consumeInput
    ruleParser.apply("-m mark ! --mark 0x2/0xffff -j DROP") should consumeInput
  }

  test("parsing target test") {
    ruleParser.apply("-j MARK --set-xmark 0x2/0xffff") should consumeInput
    ruleParser.apply("-i eth1 -j MARK --set-mark 0x2/0xffff") should consumeInput
  }

  test("target validation - mangle table") {
    tableParser.apply("""
      <<mangle>>
        <PREROUTING:ACCEPT>
          -i eth1 -j MARK --set-mark 0x2/0xffff
          -i vxlan-+ -j MARK --set-mark 0x8/0xffff
    """) should (consumeInput and beValid)

    // Invalid table.
    tableParser.apply("""
      <<nat>>
        <PREROUTING:ACCEPT>
          -d 141.23.2.3 -j MARK --set-xmark 0x1/0xfe00
    """) should (consumeInput and not (beValid))

    // Invalid chain.
    tableParser.apply("""
      <<mangle>>
        <POSTROUTING:ACCEPT>
          -d 141.23.2.3 -j MARK --set-xmark 0x1/0xfe00
    """) should (consumeInput and not (beValid))
  }
}
