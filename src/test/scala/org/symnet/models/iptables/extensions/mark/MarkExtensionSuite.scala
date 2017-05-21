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
class MarkExtensionSuite extends FunSuite with Matchers {

  implicit private val context = ParsingContext(
    List(FilteringExtension, MarkModuleLoader),
    List(FilteringExtension, MarkTargetExtension)
  )

  test("parsing mark match") {
    {
      val maybeResult = ruleParser.apply("-m mark --mark 0x2/0xffff -j ACCEPT")
      maybeResult shouldBe a [Just[_]]

      val (state, result) = maybeResult.toOption.get
      state.trim shouldBe empty
    }
    {
      val maybeResult = ruleParser.apply("-m mark ! --mark 0x2/0xffff -j DROP")
      maybeResult shouldBe a [Just[_]]

      val (state, result) = maybeResult.toOption.get
      state.trim shouldBe empty
    }
  }

  test("parsing target test") {
    {
      val maybeResult = ruleParser.apply("-j MARK --set-xmark 0x2/0xffff") 
      maybeResult shouldBe a [Just[_]]

      val (state, result) = maybeResult.toOption.get
      state.trim shouldBe empty
    }
    {
      val maybeResult = ruleParser.apply("-i eth1 -j MARK --set-mark 0x2/0xffff")
      maybeResult shouldBe a [Just[_]]

      val (state, result) = maybeResult.toOption.get
      state.trim shouldBe empty
    }
  }

  test("target validation - mangle table") {
    {
      val maybeResult = tableParser.apply("""
        <<mangle>>
          <PREROUTING:ACCEPT>
            -i eth1 -j MARK --set-mark 0x2/0xffff
            -i vxlan-+ -j MARK --set-mark 0x8/0xffff
      """)
      maybeResult shouldBe a [Just[_]]

      val (state, result) = maybeResult.toOption.get
      state.trim shouldBe empty

      val validatedResult = result.validate(ValidationContext.empty)
      validatedResult shouldBe a [Just[_]]
    }

    {
      // Invalid table.
      val maybeResult = tableParser.apply("""
        <<nat>>
          <PREROUTING:ACCEPT>
            -d 141.23.2.3 -j MARK --set-xmark 0x1/0xfe00
      """)
      maybeResult shouldBe a [Just[_]]

      val (state, result) = maybeResult.toOption.get
      state.trim shouldBe empty

      val validatedResult = result.validate(ValidationContext.empty)
      validatedResult shouldBe empty
    }

    {
      // Invalid chain.
      val maybeResult = tableParser.apply("""
        <<mangle>>
          <POSTROUTING:ACCEPT>
            -d 141.23.2.3 -j MARK --set-xmark 0x1/0xfe00
      """)
      maybeResult shouldBe a [Just[_]]

      val (state, result) = maybeResult.toOption.get
      state.trim shouldBe empty

      val validatedResult = result.validate(ValidationContext.empty)
      validatedResult shouldBe empty
    }
  }
}
