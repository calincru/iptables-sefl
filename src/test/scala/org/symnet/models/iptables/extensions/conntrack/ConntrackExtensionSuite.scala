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

@RunWith(classOf[JUnitRunner])
class ConntrackExtensionSuite extends FunSuite with Matchers
                                               with ValidationCustomMatchers {

  implicit private val context = ParsingContext.default

  test("parsing/validating conntrack match") {
    ruleParser.apply("""
      -s 192.168.0.1
      -m conntrack --ctproto tcp -j ACCEPT
    """) should consumeInput
    ruleParser.apply("""
      -o eth+
      -d 8.8.8.0/24
      -m conntrack --ctstate NEW -j ACCEPT
    """) should consumeInput

    tableParser.apply("""
      <<nat>>
      <POSTROUTING:ACCEPT>
        -m mark ! --mark 0x2/0xffff
          -m conntrack --ctstate DNAT -j SNAT --to-source 203.0.113.100
    """) should beValid
  }
}
