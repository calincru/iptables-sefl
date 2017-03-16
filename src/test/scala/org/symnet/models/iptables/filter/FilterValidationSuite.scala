// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet
package models.iptables
package filter

// scala
import org.junit.runner.RunWith
import org.scalatest.{FunSuite, Matchers}
import org.scalatest.junit.JUnitRunner

// 3rd party: scalaz
import scalaz.Maybe._

// project
import core._
import nat.SnatTarget
import types.net._
import Policy._

@RunWith(classOf[JUnitRunner])
class FilterValidationSuite extends FunSuite with Matchers {

  test("chain is valid") {
    // Success
    {
      val rule = Rule(Nil, AcceptTarget)
      val chain = BuiltinChain("INPUT", List(rule), Drop)
      val table = Table("filter", List(chain))

      table.validate shouldBe Just(table)
    }
    {
      val rule = Rule(Nil, AcceptTarget)
      val chain = UserChain("MY_CHAIN", List(rule))
      val table = Table("filter", List(chain))

      table.validate shouldBe Just(table)
    }

    // Failure
    {
      // The filter target cannot appear in the PREROUTING chain.
      val rule = Rule(Nil, AcceptTarget)
      val chain = BuiltinChain("PREROUTING", List(rule), Drop)
      val table = Table("filter", List(chain))

      table.validate shouldBe empty
    }
  }

  test("table name should be filter") {
    // Success
    {
      val rule = Rule(Nil, AcceptTarget)
      val chain = BuiltinChain("FORWARD", List(rule), Drop)
      val table = Table("filter", List(chain))

      table.validate shouldBe Just(table)
    }

    // Failure
    {
      val rule = Rule(Nil, AcceptTarget)
      val chain = BuiltinChain("FORWARD", List(rule), Drop)
      val table = Table("mangle", List(chain))

      table.validate shouldBe empty
    }
  }

  test("interface match") {
    val inIntMatch = InInterfaceMatch("eth0")
    val outIntMatch = OutInterfaceMatch("eth1")

    // Success
    {
      val rule = Rule(List(inIntMatch), AcceptTarget)
      val chain = BuiltinChain("INPUT", List(rule), Drop)
      val table = Table("filter", List(chain))

      table.validate shouldBe Just(table)
    }
    {
      val rule = Rule(List(outIntMatch),
                      SnatTarget(Ipv4(8, 8, 8, 8), None, None))
      val chain = BuiltinChain("POSTROUTING", List(rule), Drop)
      val table = Table("nat", List(chain))

      table.validate shouldBe Just(table)
    }
    {
      val otherChain = UserChain("MY_CHAIN", Nil)
      val rule = Rule(List(inIntMatch), otherChain)
      val chain = BuiltinChain("FORWARD", List(rule), Drop)
      val table = Table("filter", List(chain, otherChain))

      table.validate shouldBe Just(table)
    }

    // Failure
    {
      val rule = Rule(List(inIntMatch), AcceptTarget)
      val chain = BuiltinChain("OUTPUT", List(rule), Drop)
      val table = Table("filter", List(chain))

      table.validate shouldBe empty
    }
    {
      // Input interface match is not available in the POSTROUTING chain.
      val rule = Rule(List(inIntMatch),
                      SnatTarget(Ipv4(8, 8, 8, 8), None, None))
      val chain = BuiltinChain("POSTROUTING", List(rule), Drop)
      val table = Table("nat", List(chain))

      table.validate shouldBe empty
    }
  }

  test("ip match always true") {
    val srcIpMatch = SourceMatch(Ipv4(192, 168, 0, 1))
    val dstIpMatch = DestinationMatch(Ipv4(10, 10, 10, 1))

    // Success
    {
      val rule = Rule(List(srcIpMatch), AcceptTarget)
      val chain = BuiltinChain("FORWARD", List(rule), Drop)
      val table = Table("filter", List(chain))

      table.validate shouldBe Just(table)
    }
    {
      val rule = Rule(List(dstIpMatch), AcceptTarget)
      val chain = BuiltinChain("INPUT", List(rule), Drop)
      val table = Table("filter", List(chain))

      table.validate shouldBe Just(table)
    }
    {
      val rule = Rule(List(srcIpMatch, dstIpMatch), ReturnTarget)
      val chain = BuiltinChain("OUTPUT", List(rule), Drop)
      val table = Table("filter", List(chain))

      table.validate shouldBe Just(table)
    }

    // Failure
    {
      // It fails because the chain/rule contraints are not respected.
      val rule = Rule(List(srcIpMatch, dstIpMatch), ReturnTarget)
      val chain = BuiltinChain("PREROUTING", List(rule), Drop)
      val table = Table("filter", List(chain))

      table.validate shouldBe empty
    }
  }

  test("protocol match") {
    // Success
    {
      val rule = Rule(List(ProtocolMatch("tcp")), AcceptTarget)
      val chain = BuiltinChain("FORWARD", List(rule), Drop)
      val table = Table("filter", List(chain))

      table.validate shouldBe Just(table)
    }
    {
      val rule = Rule(List(ProtocolMatch("udp")), DropTarget)
      val chain = BuiltinChain("OUTPUT", List(rule), Drop)
      val table = Table("filter", List(chain))

      table.validate shouldBe Just(table)
    }
    {
      val rule = Rule(List(ProtocolMatch("all")),
                      SnatTarget(Ipv4(8, 8, 8, 8), None, None))
      val chain = BuiltinChain("POSTROUTING", List(rule), Drop)
      val table = Table("nat", List(chain))

      table.validate shouldBe Just(table)
    }

    // Failure
    {
      // 'tpc' is not a valid protocol.
      val rule = Rule(List(ProtocolMatch("tpc")),
                      SnatTarget(Ipv4(8, 8, 8, 8), None, None))
      val chain = BuiltinChain("POSTROUTING", List(rule), Drop)
      val table = Table("nat", List(chain))

      table.validate shouldBe empty
    }
    {
      // 'any' is not a valid protocol.
      val rule = Rule(List(ProtocolMatch("any")), DropTarget)
      val chain = BuiltinChain("OUTPUT", List(rule), Drop)
      val table = Table("filter", List(chain))

      table.validate shouldBe empty
    }
  }
}
