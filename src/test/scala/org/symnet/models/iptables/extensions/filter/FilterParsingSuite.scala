// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet
package models.iptables
package extensions.filter

// scala
import org.junit.runner.RunWith
import org.scalatest.{FunSuite, Matchers}
import org.scalatest.junit.JUnitRunner

// 3rd party: scalaz
import scalaz.Maybe._

// project
// -> core
import core.{BaseParsers, ChainTargetExtension, NegatedMatch, ParsingContext}
import core.iptParsers.{chainParser, ruleParser, tableParser}

// -> types
import types.net.Ipv4

@RunWith(classOf[JUnitRunner])
class FilterParsingSuite extends FunSuite with Matchers with BaseParsers {
  import FilterTarget.{parser => targetParser}
  import IpMatch.{dstParser, srcParser}

  ///
  /// Matchers suite.
  ///

  test("src/dst ip parser") {
    srcParser.eval("-s 192.168.0.1") shouldBe
      Just(SourceMatch(Ipv4(192, 168, 0, 1)))

    srcParser.eval("   -d   10.10.10.2/10  ") shouldBe empty

    dstParser.eval("   -d   10.10.10.2/10  ") shouldBe
      Just(DestinationMatch(Ipv4(10, 10, 10, 2, Some(10))))

    dstParser.eval("-s 192.168.0.1") shouldBe empty

    srcParser.eval("  -s   8.8.8.6/10   -s  8.8.8.8/10 ") shouldBe
      Just(SourceMatch(Ipv4(8, 8, 8, 6, Some(10))))
    srcParser.exec("  -s   8.8.8.6/10   -s  8.8.8.8/10 ") shouldBe
      Just("   -s  8.8.8.8/10 ")
  }

  test("negated src ip parser") {
    srcParser.eval("-s ! 192.168.0.1") shouldBe
      Just(NegatedMatch(SourceMatch(Ipv4(192, 168, 0, 1))))
  }

  test("multiple src/dst ip parsers") {
    some(srcParser).eval("  -s   8.8.8.6/10   -s  8.8.8.8/10 ") shouldBe
      Just(List(SourceMatch(Ipv4(8, 8, 8, 6, Some(10))),
                SourceMatch(Ipv4(8, 8, 8, 8, Some(10)))))

    many(dstParser).eval("""-d 192.168.0.10/24
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
  implicit val context = ParsingContext(
    List(FilteringExtension),
    List(FilteringExtension)
  )

  test("src/dst ip filter parsing") {
    // Success.
    assert(ruleParser.eval("-s 192.168.0.1 -j ACCEPT").isJust)
    assert(ruleParser.eval("-d 192.168.0.1 -j DROP").isJust)
    assert(ruleParser.eval("""-s 8.8.8.8/10
                               -d 192.168.0.1
                               -j DROP""").isJust)
    assert(ruleParser.eval("""-s 8.8.8.8/10
                               -s 8.8.6.6
                               -d 172.0.1.1/5
                               -j RETURN""").isJust)

    // Specifying just the target is accepted.
    assert(ruleParser.eval("-j ACCEPT").isJust)

    // Failure.
    assert(ruleParser.eval("-s 8.8.8.8/10").isEmpty) // no target
    assert(ruleParser.eval("-s 8.8.8.8/10 -j retunr").isEmpty) // invalid target
  }

  test("protocol parsing") {
    // Success
    assert(ruleParser.eval("-p tcp -j ACCEPT").isJust)
    assert(ruleParser.eval(" -p  tcp -j DROP").isJust)
    assert(ruleParser.eval(" -p  udp  -j RETURN ").isJust)
    assert(ruleParser.eval(" -p  !  udp  -j RETURN ").isJust)
    assert(ruleParser.eval(" -p  ! udp  -j RETURN ").isJust)

    // Failure
    assert(ruleParser.eval("-p tcp -j ACCEPt").isEmpty)
    assert(ruleParser.eval("-ptcp -j ACCEPT").isEmpty)
    assert(ruleParser.eval(" -p  tcp").isEmpty)
    assert(ruleParser.eval(" -p  !udp  -j RETURN ").isEmpty)
    assert(ruleParser.eval(" -p! udp  -j RETURN ").isEmpty)
    assert(ruleParser.eval("! -p udp -j DROP").isEmpty)
  }

  test("in/out interface filter parsing") {
    // Success.
    assert(ruleParser.eval("-i eth0 -j ACCEPT").isJust)
    assert(ruleParser.eval(" --in-interface  wlan0  -j DROP").isJust)
    assert(ruleParser.eval(" --out-interface  tun0  -j DROP").isJust)
    assert(ruleParser.eval(" -o tap0 -j DROP").isJust)
    assert(ruleParser.eval(" -o ! tap0 -j DROP").isJust)
    assert(ruleParser.eval(" -i ! eth1 -j ACCEPT ").isJust)

    // Prefixing the negation works too.
    assert(ruleParser.eval(" ! -i  eth1 -j ACCEPT ").isJust)

    // Failures.
    assert(ruleParser.eval(" -otap0 -j DROP").isEmpty)
    assert(ruleParser.eval(" -o tap0").isEmpty)
    assert(ruleParser.eval(" -i !eth1 -j ACCEPT ").isEmpty)
    assert(ruleParser.eval(" -i! eth1 -j ACCEPT ").isEmpty)
    assert(ruleParser.eval(" -i!eth1 -j ACCEPT ").isEmpty)
    assert(ruleParser.eval(" ! -i ! eth1 -j ACCEPT ").isEmpty)
  }

  test("chain target extension") {
    // With the top level context, which doesn't contain the (user-defined)
    // chain target extension, the second test here fails.
    {
      assert(ruleParser.eval("""-i eth0
                                -s 192.168.0.1
                                -o eth1
                                -d 172.19.8.0/24
                                -j ACCEPT""").isJust)
      assert(ruleParser.eval("""-i eth0
                                -s 192.168.0.1
                                -o eth1
                                -d 172.19.8.0/24
                                -j otherChain""").isEmpty)
    }

    // Once we add that to the target extensions, it doesn't fail anymore.
    {
      implicit val context = ParsingContext(
        List(FilteringExtension),
        List(FilteringExtension, ChainTargetExtension)
      )

      assert(ruleParser.eval("""-i eth0
                                -s 192.168.0.1
                                -o eth1
                                -d 172.19.8.0/24
                                -j otherChain""").isJust)
    }
  }

  // TODO: Add more chain/table tests.

  test("empty chain correctly parsed") {
    chainParser.eval("<PREROUTING:DROP>") shouldBe a [Just[_]]
    chainParser.eval("<my_chain>") shouldBe a [Just[_]]

    // This parses, but is invalid, so it should be caught by validation.
    chainParser.eval("<my_chain:ACCEPT>") shouldBe a [Just[_]]
  }

  test("empty table correctly parsed") {
    tableParser.eval("""
      <<filter>>
        <PREROUTING:DROP>
        <OUTPUT:DROP>
        <POSTROUTING:DROP>
    """) shouldBe a [Just[_]]

    tableParser.eval("""
      <<filter>
        <PREROUTING:DROP>
        <OUTPUT:DROP>
        <POSTROUTING:DROP>
    """) shouldBe empty
  }

  test("negation can appear on either side") {
    srcParser.eval("! -s 192.168.0.1/24") shouldBe
      Just(NegatedMatch(SourceMatch(Ipv4(192, 168, 0, 1, Some(24)))))
  }

  test("negation cannot appear on both sides at the same time") {
    srcParser.eval("! -s ! 192.168.1.1") shouldBe empty
  }
}
