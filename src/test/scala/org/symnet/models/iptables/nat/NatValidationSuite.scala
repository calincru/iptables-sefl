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
import core._
import filter.ProtocolMatch
import types.net._
import Policy._

@RunWith(classOf[JUnitRunner])
class NatValidationSuite extends FunSuite with Matchers {

  test("SNAT: table and chain should be nat/POSTROUTING") {
    // Success
    {
      val target = SnatTarget(Ipv4(192, 168, 0, 1), None, None)
      val rule = Rule(Nil, target)
      val chain = BuiltinChain("POSTROUTING", List(rule), Drop)
      val table = Table("nat", List(chain))

      table.validate shouldBe Just(table)
    }
    {
      // With optional upper bound
      val target = SnatTarget(Ipv4(192, 168, 0, 1),
                              Some(Ipv4(192, 168, 0, 100)),
                              None)
      val rule = Rule(Nil, target)
      val chain = BuiltinChain("POSTROUTING", List(rule), Drop)
      val table = Table("nat", List(chain))

      table.validate shouldBe Just(table)
    }

    // Failure
    {
      val target = SnatTarget(Ipv4(192, 168, 0, 1), None, None)
      val rule = Rule(Nil, target)
      val chain = BuiltinChain("PREROUTING", List(rule), Drop)
      val table = Table("nat", List(chain))

      table.validate shouldBe empty
    }
    {
      val target = SnatTarget(Ipv4(8, 8, 8, 8), None, None)
      val rule = Rule(Nil, target)
      val chain = BuiltinChain("OUTPUT", List(rule), Drop)
      val table = Table("nat", List(chain))

      table.validate shouldBe empty
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

      table.validate shouldBe Just(table)
    }

    // Failure
    {
      val target = SnatTarget(Ipv4(192, 168, 0, 1),
                              Some(Ipv4(192, 168, 0, 100)),
                              Some((40000, 45000)))
      val rule = Rule(Nil, target)
      val chain = BuiltinChain("POSTROUTING", List(rule), Drop)
      val table = Table("nat", List(chain))

      table.validate shouldBe empty
    }
  }

  test("DNAT: table and chain should be nat/(PREROUTING or OUTPUT)") {
    // Success
    {
      val target = DnatTarget(Ipv4(192, 168, 0, 1), None, None)
      val rule = Rule(Nil, target)
      val chain = BuiltinChain("PREROUTING", List(rule), Drop)
      val table = Table("nat", List(chain))

      table.validate shouldBe Just(table)
    }
    {
      // With optional upper bound
      val target = DnatTarget(Ipv4(192, 168, 0, 1),
                              Some(Ipv4(192, 168, 0, 100)),
                              None)
      val rule = Rule(Nil, target)
      val chain = BuiltinChain("OUTPUT", List(rule), Drop)
      val table = Table("nat", List(chain))

      table.validate shouldBe Just(table)
    }

    // Failure
    {
      val target = DnatTarget(Ipv4(192, 168, 0, 1), None, None)
      val rule = Rule(Nil, target)
      val chain = BuiltinChain("POSTROUTING", List(rule), Drop)
      val table = Table("nat", List(chain))

      table.validate shouldBe empty
    }
    {
      val target = DnatTarget(Ipv4(8, 8, 8, 8), None, None)
      val rule = Rule(Nil, target)
      val chain = BuiltinChain("INPUT", List(rule), Drop)
      val table = Table("nat", List(chain))

      table.validate shouldBe empty
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

      table.validate shouldBe Just(table)
    }

    // Failure
    {
      val target = DnatTarget(Ipv4(192, 168, 0, 1),
                              Some(Ipv4(192, 168, 0, 100)),
                              Some((40000, 45000)))
      val rule = Rule(Nil, target)
      val chain = BuiltinChain("PREROUTING", List(rule), Drop)
      val table = Table("nat", List(chain))

      table.validate shouldBe empty
    }
  }


}
