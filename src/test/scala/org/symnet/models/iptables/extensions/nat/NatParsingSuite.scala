// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet
package models.iptables
package extensions.nat

// scala
import org.junit.runner.RunWith
import org.scalatest.{FunSuite, Matchers}
import org.scalatest.junit.JUnitRunner

// 3rd party:
// -> scalaz
import scalaz.Maybe._

// project
// -> core
import core.ParsingContext
import core.iptParsers.{ruleParser, chainParser}
import extensions.filter._
import extensions.tcp.TcpExtension

// -> types
import types.net._

@RunWith(classOf[JUnitRunner])
class NatParsingSuite extends FunSuite with Matchers
                                       with ValidationCustomMatchers {

  test("source nat test") {
    implicit val context = ParsingContext(
      List(FilteringExtension),
      List(SnatTargetExtension, FilteringExtension)
    )

    // Success
    ruleParser.apply("""
      -s 192.168.0.5
      -j SNAT --to-source 141.85.200.1
    """) should consumeInput
    ruleParser.apply("""
      -s 192.168.0.5
      -j SNAT --to-source 141.85.200.1-141.85.200.200
    """) should consumeInput
    ruleParser.apply("""
      -s 192.168.0.5
      -j SNAT --to-source 141.85.200.1:2000-3000
    """) should consumeInput
    ruleParser.apply("""
      -s 172.19.0.0/16
      -j SNAT --to-source 141.85.200.1-141.85.200.10:200-300
    """) should consumeInput

    // Failure
    ruleParser.apply(
      "-s 192.168.0.0/24 -j SNAT") shouldBe empty
    ruleParser.apply(
      "-s 192.168.0.1 -j snat --to-source 8.8.8.8") shouldBe empty
    ruleParser.apply(
      "-s 8.8.8.8 -j dnat --to-destination 192.168.0.10") shouldBe empty

    // DNAT is not loaded
    ruleParser.apply("""
      -d 141.85.200.1
      -j DNAT --to-destination 192.168.0.1
    """) shouldBe empty
  }

  test("destination nat test") {
    implicit val context = ParsingContext(
      List(FilteringExtension),
      List(DnatTargetExtension, FilteringExtension)
    )

    // Success
    ruleParser.apply("""
      -d 140.85.200.1
      -j DNAT --to-destination 192.168.0.1
    """) should consumeInput
    ruleParser.apply("""
      -s 141.85.200.1
      -j DNAT --to-destination 192.168.0.1-192.168.0.10
    """) should consumeInput
    ruleParser.apply("""
      -s 141.85.200.1
      -j DNAT --to-destination 192.168.0.1:0-10
    """) should consumeInput
    ruleParser.apply("""
      -s 192.168.0.1
      -j DNAT --to-destination 192.168.0.1-192.168.0.10:0-100
    """) should consumeInput

    // Failure
    ruleParser.apply(
      "-s 192.168.0.0/24 -j DNAT") shouldBe empty
    ruleParser.apply(
      "-s 8.8.8.8 -j dnat --to-destination 192.168.0.10") shouldBe empty
    ruleParser.apply(
      "-s 192.168.0.1 -j dnat --to-source 8.8.8.8") shouldBe empty

    // SNAT is not loaded.
    ruleParser.apply("""
      -s 192.168.0.5
      -j SNAT --to-source 141.85.200.1
    """) shouldBe empty
  }

  test("masquerade test") {
    implicit val context = ParsingContext(
      List(FilteringExtension),
      List(MasqueradeTargetExtension, FilteringExtension)
    )

    // Success
    ruleParser.apply("""
      -o eth0
      -p tcp
      -j MASQUERADE
    """) should consumeInput
    ruleParser.apply("""
      -o eth0
      -p tcp
      -j MASQUERADE --to-ports 50000-55000
    """) should consumeInput
    ruleParser.apply("""
      -d 8.8.8.6
      -o eth0
      -p tcp
      -j MASQUERADE --to-ports 51002""") should consumeInput

    // Invalid unterminated --to-ports option doesn't get parsed. It will
    // probably fail next, in a real context.
    ruleParser.exec("""
      -o eth0
      -p tcp
      -j MASQUERADE --to-ports""") shouldBe Just(" --to-ports")

    // Invalid port number, too big.
    ruleParser.exec("""
      -d 8.8.8.6
      -o eth0
      -p tcp
      -j MASQUERADE --to-ports 510002""") shouldBe Just("2")

    // Failure
    ruleParser.apply("""
      -o eth0
      -p tcp
      -j MASQUARADE
    """) shouldBe empty // masquArade
  }

  test("redirect test") {
    implicit val context = ParsingContext(
      List(FilteringExtension, TcpExtension),
      List(RedirectTargetExtension, FilteringExtension)
    )

    // Success
    ruleParser.apply("""
      -i eth0
      -p tcp
      -j REDIRECT --to-ports 50001
    """) should consumeInput
    ruleParser.apply("""
      -d 169.254.169.254/32
      -i qr-+
      -p tcp
      --dport 80
      -j REDIRECT --to-ports 9697-10000
    """) should consumeInput
    ruleParser.apply("""
      -d 169.254.169.254/32
      -i qr-+
      -j REDIRECT
    """) should consumeInput
  }
}
