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
// -> core
import core.{Parsing, ParsingContext}
import Parsing.{ruleParser, chainParser}
import Parsing.Combinators._

// -> types
import types.net.Ipv4

@RunWith(classOf[JUnitRunner])
class FilterExtensionSuite extends FunSuite with Matchers {
  import FilteringExtension.Impl._

  ///
  /// Matchers suite.
  ///

  test("src/dst ip parser") {
    srcIpMatchParser.eval("-s 192.168.0.1") shouldBe
      Just(SourceMatch(Ipv4(192, 168, 0, 1)))

    srcIpMatchParser.eval("   -d   10.10.10.2/10  ") shouldBe empty

    dstIpMatchParser.eval("   -d   10.10.10.2/10  ") shouldBe
      Just(DestinationMatch(Ipv4(10, 10, 10, 2, Some(10))))

    dstIpMatchParser.eval("-s 192.168.0.1") shouldBe empty

    srcIpMatchParser.eval("  -s   8.8.8.6/10   -s  8.8.8.8/10 ") shouldBe
      Just(SourceMatch(Ipv4(8, 8, 8, 6, Some(10))))
    srcIpMatchParser.exec("  -s   8.8.8.6/10   -s  8.8.8.8/10 ") shouldBe
      Just("   -s  8.8.8.8/10 ")
  }

  test("negated src ip parser") {
    srcIpMatchParser.eval("-s ! 192.168.0.1") shouldBe
      Just(SourceMatch(Ipv4(192, 168, 0, 1), negated=true))
  }

  test("multiple src/dst ip parsers") {
    some(srcIpMatchParser).eval("  -s   8.8.8.6/10   -s  8.8.8.8/10 ") shouldBe
      Just(List(SourceMatch(Ipv4(8, 8, 8, 6, Some(10))),
                SourceMatch(Ipv4(8, 8, 8, 8, Some(10)))))

    many(dstIpMatchParser).eval("""-d 192.168.0.10/24
                                   -d 192.168.0.11/24
                                   -d 0.0.0.0""") shouldBe
      Just(List(DestinationMatch(Ipv4(192, 168, 0, 10, Some(24))),
                DestinationMatch(Ipv4(192, 168, 0, 11, Some(24))),
                DestinationMatch(Ipv4(0, 0, 0, 0))))
  }

  test("target parser") {
    targetParser.eval("-j ACCEPT") shouldBe Just(AcceptTarget)
    targetParser.eval("-j DROP") shouldBe Just(DropTarget)
    targetParser.eval("-j RETURN") shouldBe Just(ReturnTarget)

    targetParser.eval("-j accept") shouldBe empty
    targetParser.eval("-j DrOp") shouldBe empty
    targetParser.eval("-j ReTuRn") shouldBe empty
  }


  ///
  /// Rule parsing suite.
  ///

  // Construct an implicit ParsingContext consisting only of the filtering
  // parser.
  implicit val context = new ParsingContext {
    val matchExtensions  = List(FilteringExtension)
    val targetExtensions = List(FilteringExtension)
  }

  test("simple rule parsing") {
    // Success.
    assert(!ruleParser.eval("-s 192.168.0.1 -j ACCEPT").isEmpty)
    assert(!ruleParser.eval("-d 192.168.0.1 -j DROP").isEmpty)
    assert(!ruleParser.eval("""-s 8.8.8.8/10
                               -d 192.168.0.1
                               -j DROP""").isEmpty)
    assert(!ruleParser.eval("""-s 8.8.8.8/10
                               -s 8.8.6.6
                               -d 172.0.1.1/5
                               -j RETURN""").isEmpty)

    // Failure.
    assert(ruleParser.eval("-s 8.8.8.8/10").isEmpty) // no target
    assert(ruleParser.eval("-j ACCEPT").isEmpty) // just target
    assert(ruleParser.eval("-s 8.8.8.8/10 -j retunr").isEmpty) // invalid target
  }

  // TODO(calincru): Tests for in/out interface and protocols.
}
