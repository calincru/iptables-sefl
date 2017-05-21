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
import core.iptParsers.{ruleParser, chainParser, tableParser}
import extensions.filter._

@RunWith(classOf[JUnitRunner])
class MarkExtensionSuite extends FunSuite with Matchers {

  implicit private val context = ParsingContext(
    // TODO: Remove `MarkMatchExtension' once module loading works.
    List(FilteringExtension, MarkModuleLoader, MarkMatchExtension),
    List(FilteringExtension, MarkTargetExtension)
  )

  test("parsing mark match") {
    ruleParser.eval("-m mark --mark 0x2/0xffff -j ACCEPT") shouldBe a [Just[_]]
    ruleParser.eval("-m mark ! --mark 0x2/0xffff -j DROP") shouldBe a [Just[_]]
  }

  test("parsing target test") {
    ruleParser.eval("-j MARK --set-xmark 0x2/0xffff") shouldBe a [Just[_]]
    ruleParser.eval("-i eth1 -j MARK --set-mark 0x2/0xffff") shouldBe a [Just[_]]
  }

  test("target validation - mangle table") {
    tableParser.eval("""
      <<mangle>>
        <PREROUTING:ACCEPT>
          -i eth1 -j MARK --set-mark 0x2/0xffff
          -i vxlan-+ -j MARK --set-mark 0x8/0xffff
    """).flatMap(_.validate(ValidationContext.empty)) shouldBe a [Just[_]]

    // Invalid table.
    tableParser.eval("""
      <<nat>>
        <PREROUTING:ACCEPT>
          -d 141.23.2.3 -j MARK --set-xmark 0x1/0xfe00
    """).flatMap(_.validate(ValidationContext.empty)) shouldBe empty

    // Invalid chain.
    tableParser.eval("""
      <<mangle>>
        <POSTROUTING:ACCEPT>
          -d 141.23.2.3 -j MARK --set-xmark 0x1/0xfe00
    """).flatMap(_.validate(ValidationContext.empty)) shouldBe empty
  }
}
