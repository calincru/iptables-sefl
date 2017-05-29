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

// TODO: Change all these `eval's to sequences of apply/asserts.

@RunWith(classOf[JUnitRunner])
class NatParsingSuite extends FunSuite with Matchers {

  test("source nat test") {
    implicit val context = ParsingContext(
      List(FilteringExtension),
      List(SnatTargetExtension, FilteringExtension)
    )

    // Success
    ruleParser.eval(
      """-s 192.168.0.5
         -j SNAT
         --to-source 141.85.200.1""") shouldBe a [Just[_]]
    ruleParser.eval(
      """-s 192.168.0.5
         -j SNAT
         --to-source 141.85.200.1-141.85.200.200""") shouldBe a [Just[_]]
    ruleParser.eval(
      """-s 192.168.0.5
         -j SNAT
         --to-source 141.85.200.1:2000-3000""") shouldBe a [Just[_]]
    ruleParser.eval(
      """-s 172.19.0.0/16
         -j SNAT
         --to-source 141.85.200.1-141.85.200.10:200-300""") shouldBe a [Just[_]]

    // Failure
    ruleParser.eval(
      "-s 192.168.0.0/24 -j SNAT") shouldBe empty
    ruleParser.eval(
      "-s 192.168.0.1 -j snat --to-source 8.8.8.8") shouldBe empty
    ruleParser.eval(
      "-s 8.8.8.8 -j dnat --to-destination 192.168.0.10") shouldBe empty

    // DNAT is not loaded
    ruleParser.eval(
      """-d 141.85.200.1
         -j DNAT
         --to-destination 192.168.0.1""") shouldBe empty
  }

  test("destination nat test") {
    implicit val context = ParsingContext(
      List(FilteringExtension),
      List(DnatTargetExtension, FilteringExtension)
    )

    // Success
    ruleParser.eval(
      """-d 140.85.200.1
         -j DNAT
         --to-destination 192.168.0.1""") shouldBe a [Just[_]]
    ruleParser.eval(
      """-s 141.85.200.1
         -j DNAT
         --to-destination 192.168.0.1-192.168.0.10""") shouldBe a [Just[_]]
    ruleParser.eval(
      """-s 141.85.200.1
         -j DNAT
         --to-destination 192.168.0.1:0-10""") shouldBe a [Just[_]]
    ruleParser.eval(
      """-s 192.168.0.1
         -j DNAT
         --to-destination 192.168.0.1-192.168.0.10:0-100""") shouldBe a [Just[_]]

    // Failure
    ruleParser.eval(
      "-s 192.168.0.0/24 -j DNAT") shouldBe empty
    ruleParser.eval(
      "-s 8.8.8.8 -j dnat --to-destination 192.168.0.10") shouldBe empty
    ruleParser.eval(
      "-s 192.168.0.1 -j dnat --to-source 8.8.8.8") shouldBe empty

    // SNAT is not loaded.
    ruleParser.eval(
      """-s 192.168.0.5
         -j SNAT
         --to-source 141.85.200.1""") shouldBe empty
  }

  test("masquerade test") {
    implicit val context = ParsingContext(
      List(FilteringExtension),
      List(MasqueradeTargetExtension, FilteringExtension)
    )

    // Success
    ruleParser.eval(
      "-o eth0 -p tcp -j MASQUERADE") shouldBe a [Just[_]]
    ruleParser.eval(
      "-o eth0 -p tcp -j MASQUERADE --to-ports 50000-55000") shouldBe a [Just[_]]
    ruleParser.eval(
      """-d 8.8.8.6
         -o eth0
         -p tcp
         -j MASQUERADE
         --to-ports 51002""") shouldBe a [Just[_]]

    // Invalid unterminated --to-ports option doesn't get parsed. It will
    // probably fail next, in a real context.
    ruleParser.exec(
      "-o eth0 -p tcp -j MASQUERADE --to-ports") shouldBe Just(" --to-ports")

    // Invalid port number, too big.
    ruleParser.exec(
      """-d 8.8.8.6
         -o eth0
         -p tcp
         -j MASQUERADE
         --to-ports 510002""") shouldBe Just("2")

    // Failure
    ruleParser.eval(
      "-o eth0 -p tcp -j MASQUARADE") shouldBe empty // masquArade
  }

  test("redirect test") {
    implicit val context = ParsingContext(
      List(FilteringExtension, TcpExtension),
      List(RedirectTargetExtension, FilteringExtension)
    )

    // Success
    ruleParser.eval(
      """-i eth0
         -p tcp
         -j REDIRECT --to-ports 50001""") shouldBe a [Just[_]]
    ruleParser.eval(
      """-d 169.254.169.254/32
         -i qr-+
         -p tcp
         --dport 80
         -j REDIRECT --to-ports 9697-10000""") shouldBe a [Just[_]]
    ruleParser.eval(
      "-d 169.254.169.254/32 -i qr-+ -j REDIRECT") shouldBe a [Just[_]]
  }
}
