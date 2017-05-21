// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet
package models.iptables
package extensions.connmark

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
class ConnmarkExtensionSuite extends FunSuite with Matchers {

  implicit private val context = ParsingContext(
    List(FilteringExtension, ConnmarkModuleLoader),
    List(FilteringExtension, ConnmarkTargetExtension)
  )

  test("parsing connmark match") {
    {
      val maybeResult = ruleParser.apply("""
        -o qg-09d66f0a-46
        -m connmark --mark 0x0/0xffff0000
        -j CONNMARK --save-mark --nfmask 0xffff0000 --ctmask 0xffff0000
      """)
      maybeResult shouldBe a [Just[_]]

      val (state, result) = maybeResult.toOption.get
      state.trim shouldBe empty
    }

    {
      val maybeResult = tableParser.apply("""
        <<mangle>>
        <PREROUTING:ACCEPT>
          -m connmark ! --mark 0x0/0xffff0000
            -j CONNMARK --restore-mark --nfmask 0xffff0000 --ctmask 0xffff0000
      """)
      maybeResult shouldBe a [Just[_]]

      val (state, result) = maybeResult.toOption.get
      state.trim shouldBe empty

      val validatedResult = result.validate(ValidationContext.empty)
      validatedResult shouldBe a [Just[_]]
    }
  }
}
