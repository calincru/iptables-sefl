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
class ConnmarkExtensionSuite extends FunSuite with Matchers
                                              with ValidationCustomMatchers {

  implicit private val context = ParsingContext(
    List(FilteringExtension, ConnmarkModuleLoader),
    List(FilteringExtension, ConnmarkTargetExtension)
  )

  test("parsing connmark match") {
    ruleParser.apply("""
      -o qg-09d66f0a-46
      -m connmark --mark 0x0/0xffff0000
      -j CONNMARK --save-mark --nfmask 0xffff0000 --ctmask 0xffff0000
    """) should consumeInput

    tableParser.apply("""
      <<mangle>>
      <PREROUTING:ACCEPT>
        -m connmark ! --mark 0x0/0xffff0000
          -j CONNMARK --restore-mark --nfmask 0xffff0000 --ctmask 0xffff0000
      """) should beValid
  }
}
