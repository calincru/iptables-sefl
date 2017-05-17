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

// 3rd party: scalaz
import scalaz.Maybe._

// project
import types.net._
import core._
import extensions.filter.ProtocolMatch
import Policy._

@RunWith(classOf[JUnitRunner])
class NatValidationSuite extends FunSuite with Matchers {

  private val emptyCtx = ValidationContext.empty

  test("SNAT: table and chain should be nat/POSTROUTING") {
    // Success
    {
      val target = SnatTarget(Ipv4(192, 168, 0, 1), None, None)
      val rule = Rule(Nil, target)
      val chain = BuiltinChain("POSTROUTING", List(rule), Drop)
      val table = Table("nat", List(chain))

      table.validate(emptyCtx) shouldBe Just(table)
    }
    {
      // With optional upper bound
      val target = SnatTarget(Ipv4(192, 168, 0, 1),
                              Some(Ipv4(192, 168, 0, 100)),
                              None)
      val rule = Rule(Nil, target)
      val chain = BuiltinChain("POSTROUTING", List(rule), Drop)
      val table = Table("nat", List(chain))

      table.validate(emptyCtx) shouldBe Just(table)
    }

    // Failure
    {
      val target = SnatTarget(Ipv4(192, 168, 0, 1), None, None)
      val rule = Rule(Nil, target)
      val chain = BuiltinChain("PREROUTING", List(rule), Drop)
      val table = Table("nat", List(chain))

      table.validate(emptyCtx) shouldBe empty
    }
    {
      val target = SnatTarget(Ipv4(8, 8, 8, 8), None, None)
      val rule = Rule(Nil, target)
      val chain = BuiltinChain("OUTPUT", List(rule), Drop)
      val table = Table("nat", List(chain))

      table.validate(emptyCtx) shouldBe empty
    }
  }

  test("SNAT: optional port only when protocol matches tcp/udp") {
    // Success
    {
      val protocolMatch = ProtocolMatch("tcp")
      val target = SnatTarget(Ipv4(192, 168, 0, 1),
                              Some(Ipv4(192, 168, 0, 100)),
                              Some((40000, 45000)))
      val rule = Rule(List(protocolMatch), target)
      val chain = BuiltinChain("POSTROUTING", List(rule), Drop)
      val table = Table("nat", List(chain))

      table.validate(emptyCtx) shouldBe Just(table)
    }

    // Failure
    {
      val target = SnatTarget(Ipv4(192, 168, 0, 1),
                              Some(Ipv4(192, 168, 0, 100)),
                              Some((40000, 45000)))
      val rule = Rule(Nil, target)
      val chain = BuiltinChain("POSTROUTING", List(rule), Drop)
      val table = Table("nat", List(chain))

      table.validate(emptyCtx) shouldBe empty
    }
  }

  test("DNAT: table and chain should be nat/(PREROUTING or OUTPUT)") {
    // Success
    {
      val target = DnatTarget(Ipv4(192, 168, 0, 1), None, None)
      val rule = Rule(Nil, target)
      val chain = BuiltinChain("PREROUTING", List(rule), Drop)
      val table = Table("nat", List(chain))

      table.validate(emptyCtx) shouldBe Just(table)
    }
    {
      // With optional upper bound
      val target = DnatTarget(Ipv4(192, 168, 0, 1),
                              Some(Ipv4(192, 168, 0, 100)),
                              None)
      val rule = Rule(Nil, target)
      val chain = BuiltinChain("OUTPUT", List(rule), Drop)
      val table = Table("nat", List(chain))

      table.validate(emptyCtx) shouldBe Just(table)
    }

    // Failure
    {
      val target = DnatTarget(Ipv4(192, 168, 0, 1), None, None)
      val rule = Rule(Nil, target)
      val chain = BuiltinChain("POSTROUTING", List(rule), Drop)
      val table = Table("nat", List(chain))

      table.validate(emptyCtx) shouldBe empty
    }
    {
      val target = DnatTarget(Ipv4(8, 8, 8, 8), None, None)
      val rule = Rule(/* no protocol match here */ Nil, target)
      val chain = BuiltinChain("INPUT", List(rule), Drop)
      val table = Table("nat", List(chain))

      table.validate(emptyCtx) shouldBe empty
    }
  }

  test("DNAT: optional port only when protocol matches tcp/udp") {
    // Success
    {
      val protocolMatch = ProtocolMatch("udp")
      val target = DnatTarget(Ipv4(192, 168, 0, 1),
                              Some(Ipv4(192, 168, 0, 100)),
                              Some((40000, 45000)))
      val rule = Rule(List(protocolMatch), target)
      val chain = BuiltinChain("OUTPUT", List(rule), Drop)
      val table = Table("nat", List(chain))

      table.validate(emptyCtx) shouldBe Just(table)
    }

    // Failure
    {
      val target = DnatTarget(Ipv4(192, 168, 0, 1),
                              Some(Ipv4(192, 168, 0, 100)),
                              Some((40000, 45000)))
      val rule = Rule(/* no protocol match here */ Nil, target)
      val chain = BuiltinChain("PREROUTING", List(rule), Drop)
      val table = Table("nat", List(chain))

      table.validate(emptyCtx) shouldBe empty
    }
  }

  test("MASQUERADE: table and chain should be nat/POSTROUTING") {
    // Success
    {
      val target = MasqueradeTarget(None, None)
      val rule = Rule(Nil, target)
      val chain = BuiltinChain("POSTROUTING", List(rule), Drop)
      val table = Table("nat", List(chain))

      table.validate(emptyCtx) shouldBe Just(table)
    }

    // Failure
    {
      // Invalid chain.
      val target = MasqueradeTarget(None, None)
      val rule = Rule(Nil, target)
      val chain = BuiltinChain("PREROUTING", List(rule), Drop)
      val table = Table("nat", List(chain))

      table.validate(emptyCtx) shouldBe empty
    }
    {
      // Invalid chain.
      val protocolMatch = ProtocolMatch("tcp")
      val target = MasqueradeTarget(Some(10000), None)
      val rule = Rule(List(protocolMatch), target)
      val chain = BuiltinChain("OUTPUT", List(rule), Drop)
      val table = Table("nat", List(chain))

      table.validate(emptyCtx) shouldBe empty
    }
  }

  test("MASQUERADE: optional ports only when protocol matches tcp/udp") {
    // Success
    {
      // With optional lower port
      val protocolMatch = ProtocolMatch("tcp")
      val target = MasqueradeTarget(Some(40000), None)
      val rule = Rule(List(protocolMatch), target)
      val chain = BuiltinChain("POSTROUTING", List(rule), Drop)
      val table = Table("nat", List(chain))

      table.validate(emptyCtx) shouldBe Just(table)
    }
    {
      // With optional port range
      val protocolMatch = ProtocolMatch("udp")
      val target = MasqueradeTarget(Some(40000), Some(45000))
      val rule = Rule(List(protocolMatch), target)
      val chain = BuiltinChain("POSTROUTING", List(rule), Drop)
      val table = Table("nat", List(chain))

      table.validate(emptyCtx) shouldBe Just(table)
    }

    // Failure
    {
      // If the upper bound port is given, then so the lower bound port should.
      val protocolMatch = ProtocolMatch("udp")
      val target = MasqueradeTarget(None, Some(45000)) //<-- issue here
      val rule = Rule(List(protocolMatch), target)
      val chain = BuiltinChain("POSTROUTING", List(rule), Drop)
      val table = Table("nat", List(chain))

      table.validate(emptyCtx) shouldBe empty
    }
    {
      // Protocol match not specified even though port is specified.
      val target = MasqueradeTarget(Some(15000), None)
      val rule = Rule(Nil, target) //<-- issue here (Nil)
      val chain = BuiltinChain("POSTROUTING", List(rule), Drop)
      val table = Table("nat", List(chain))

      table.validate(emptyCtx) shouldBe empty
    }
    {
      // Protocol match not specified even though port range is specified.
      val target = MasqueradeTarget(Some(15000), Some(17000))
      val rule = Rule(Nil, target) //<-- issue here (Nil)
      val chain = BuiltinChain("POSTROUTING", List(rule), Drop)
      val table = Table("nat", List(chain))

      table.validate(emptyCtx) shouldBe empty
    }
  }
}
