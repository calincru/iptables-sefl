// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet
package models.iptables
package nat

// scala
import org.junit.runner.RunWith
import org.scalatest.{FunSuite, Matchers}
import org.scalatest.junit.JUnitRunner

// 3rd party: scalaz
import scalaz.Maybe._

// project
// -> core
import core.ParsingContext
import core.iptParsers.{ruleParser, chainParser}
import filter._

// -> types
import types.net._

@RunWith(classOf[JUnitRunner])
class NatParsingSuite extends FunSuite with Matchers {

  test("source nat test") {
    implicit val context = new ParsingContext {
      val matchExtensions  = List(FilteringExtension)
      val targetExtensions = List(SnatTargetExtension, FilteringExtension)
    }

    // Success
    ruleParser.eval("""-s 192.168.0.5
                       -j SNAT
                       --to-source 141.85.200.1""").isJust
    ruleParser.eval("""-s 192.168.0.5
                       -j SNAT
                       --to-source 141.85.200.1-141.85.200.200""").isJust
    ruleParser.eval("""-s 192.168.0.5
                       -j SNAT
                       --to-source 141.85.200.1:2000-3000""").isJust
    ruleParser.eval("""-s 172.19.0.0/16
                       -j SNAT
                       --to-source 141.85.200.1-141.85.200.10:200-300""").isJust

    // Failure
    ruleParser.eval("-s 192.168.0.0/24 -j SNAT").isEmpty
    ruleParser.eval("-s 192.168.0.1 -j snat --to-source 8.8.8.8").isEmpty
    ruleParser.eval("-s 8.8.8.8 -j dnat --to-destination 192.168.0.10").isEmpty

    // dnat is not loaded
    ruleParser.eval("""-d 141.85.200.1
                       -j DNAT
                       --to-destination 192.168.0.1""").isJust
  }

  test("destination nat test") {
    implicit val context = new ParsingContext {
      val matchExtensions  = List(FilteringExtension)
      val targetExtensions = List(DnatTargetExtension, FilteringExtension)
    }

    // Success
    ruleParser.eval("""-d 141.85.200.1
                       -j DNAT
                       --to-destination 192.168.0.1""").isJust
    ruleParser.eval("""-s 141.85.200.1
                       -j DNAT
                       --to-destination 192.168.0.1-192.168.0.10""").isJust
    ruleParser.eval("""-s 141.85.200.1
                       -j DNAT
                       --to-destination 192.168.0.1:0-10""").isJust
    ruleParser.eval("""-s 192.168.0.1
                       -j DNAT
                       --to-destination 192.168.0.1-192.168.0.10:0-100""").isJust

    // Failure
    ruleParser.eval("-s 192.168.0.0/24 -j DNAT").isEmpty
    ruleParser.eval("-s 8.8.8.8 -j dnat --to-destination 192.168.0.10").isEmpty
    ruleParser.eval("-s 192.168.0.1 -j dnat --to-source 8.8.8.8").isEmpty
    ruleParser.eval("""-s 192.168.0.5
                       -j SNAT
                       --to-source 141.85.200.1""").isJust // snat is not loaded
  }

  test("masquerade test") {
    implicit val context = new ParsingContext {
      val matchExtensions  = List(FilteringExtension)
      val targetExtensions = List(MasqueradeTargetExtension, FilteringExtension)
    }

    // Success
    ruleParser.eval("-o eth0 -p tcp -j MASQUERADE").isJust
    ruleParser.eval("-o eth0 -p tcp -j MASQUERADE --to-ports 50000-55000").isJust
    ruleParser.eval("""-d 8.8.8.6
                       -o eth0
                       -p tcp
                       -j MASQUERADE
                       --to-ports 51002""").isJust

    // Failure
    ruleParser.eval("-o eth0 -p tcp -j MASQUARADE").isJust // masquArade
    ruleParser.eval("-o eth0 -p tcp -j MASQUERADE --to-ports").isJust // no port
    ruleParser.eval("""-d 8.8.8.6
                       -o eth0
                       -p tcp
                       -j MASQUERADE
                       --to-ports 510002""").isJust // invalid port
  }
}
