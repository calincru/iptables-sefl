// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet
package models.iptables.core

// scala
import org.junit.runner.RunWith
import org.scalatest.{FunSuite, Matchers}
import org.scalatest.junit.JUnitRunner

// 3rd party: scalaz
import scalaz.Maybe._

// project
import types.net.Ipv4
import Parsing._

@RunWith(classOf[JUnitRunner])
class CoreParsingSuite extends FunSuite with Matchers {

  ///
  /// Combinators testing suite.
  ///
  import Combinators._

  test("optional ana false") {
    val result = optional(parseChar('b')).eval("ana")
    result shouldBe Just(None)
  }

  test("optional ana consumes 'a'") {
    val parser = optional(parseChar('a'))
    val value = parser.eval("ana")
    val state = parser.exec("ana")

    value shouldBe Just(Some('a'))
    state shouldBe Just("na")
  }

  test("some chars") {
    val parser = some(parseChar('a'))
    val value = parser.eval("aana").map(_.mkString) // Maybe is not Functor?!
    val state = parser.exec("aana").map(_.mkString)

    value shouldBe Just("aa")
    state shouldBe Just("na")
  }

  test("some none chars") {
    val parser = some(parseChar('b'))
    val value = parser.eval("ana").map(_.mkString)
    val state = parser.exec("ana").map(_.mkString)

    value shouldBe empty
    state shouldBe empty
  }

  test("many chars") {
    val parser = many(parseChar('a'))
    val value = parser.eval("aana").map(_.mkString)
    val state = parser.exec("aana").map(_.mkString)

    value shouldBe Just("aa")
    state shouldBe Just("na")
  }

  test("many none chars") {
    val parser = many(parseChar('b'))
    val value = parser.eval("ana").map(_.mkString)
    val state = parser.exec("ana").map(_.mkString)

    value shouldBe Just("")
    state shouldBe Just("ana")
  }

  test("atMost combinator succeeds") {
    val parser = Combinators.atMost(2, parseChar('a'))
    val value = parser.eval("aaa").map(_.mkString)
    val state = parser.exec("aaa").map(_.mkString)

    value shouldBe Just("aa")
    state shouldBe Just("a")
  }

  test("oneOf selects second") {
    val input = "  ana"
    val parser = Combinators.oneOf(parseString("ana"), spacesParser)
    val value = parser.eval(input)
    val state = parser.exec(input)

    value shouldBe Just("  ")
    state shouldBe Just("ana")
  }

  ///
  /// Core parsers testing suite.
  ///

  test("parseCharIf ana") {
    val result = parseCharIf(_ == 'a').eval("ana")
    result shouldBe Just('a')
  }

  test("parseCharIf false") {
    val result = parseCharIf(_ == 'b').eval("ana")
    result shouldBe empty
  }

  test("parseCharIf empty") {
    val result = parseCharIf(_ == 'a').eval("")
    result shouldBe empty
  }

  test("parseChar ana") {
    val result = parseChar('a').eval("ana")
    result shouldBe Just('a')
  }

  test("parseChar false") {
    val result = parseChar('b').eval("ana")
    result shouldBe empty
  }

  test("parseChar empty") {
    val parser = parseChar('b')
    val value = parser.eval("")
    val state = parser.exec("")

    value shouldBe empty
    state shouldBe empty
  }

  test("spacesParser eats") {
    val input = "  ana"
    val spaces = spacesParser.eval(input)
    val state = spacesParser.exec(input)

    spaces shouldBe Just("  ")
    state shouldBe Just("ana")
  }

  test("parse one string") {
    val parser = parseString("ana")
    val value = parser.eval("ana are mere")
    val state = parser.exec("ana are mere")

    value shouldBe Just("ana")
    state shouldBe Just(" are mere")
  }

  test("parse string fails") {
    val parser = parseString("anb")
    val value = parser.eval("ana are mere")
    val state = parser.exec("ana are mere")

    value shouldBe empty
    state shouldBe empty
  }

  test("parse string orElse") {
    val lhsParser = parseString("ana")
    val rhsParser = parseString("anb")
    val value = (lhsParser <<|> rhsParser).eval("ana are mere")
    val state = (lhsParser <<|> rhsParser).exec("ana are mere")

    value shouldBe Just("ana")
    state shouldBe Just(" are mere")
  }

  test("parse string orElse priority") {
    val lhsParser = parseString("ana")
    val rhsParser = parseString("ana ")
    val value = (lhsParser <<|> rhsParser).eval("ana are mere")
    val state = (lhsParser <<|> rhsParser).exec("ana are mere")

    value shouldBe Just("ana")
    state shouldBe Just(" are mere")
  }

  test("parse string orElse priority reversed") {
    val lhsParser = parseString("ana ")
    val rhsParser = parseString("ana")
    val value = (lhsParser <<|> rhsParser).eval("ana are mere")
    val state = (lhsParser <<|> rhsParser).exec("ana are mere")

    value shouldBe Just("ana ")
    state shouldBe Just("are mere")
  }

  test("atMost on digits") {
    val digitsParser = Combinators.atMost(3, digitParser)
    val result = digitsParser.eval("1234")

    result shouldBe Just(List(1,2,3))
  }

  test("parsing bytes") {
    byteParser.eval("123asda") shouldBe Just(123)
    byteParser.eval("255 ") shouldBe Just(255)
    byteParser.exec("255 ") shouldBe Just(" ")
    byteParser.eval("256 ") shouldBe empty
    byteParser.exec("256 ") shouldBe empty

    byteParser.eval("-155 ") shouldBe empty
  }

  test("parsing ports") {
    portParser.eval("8080") shouldBe Just(8080)
    portParser.eval("0") shouldBe Just(0)
    portParser.eval("65535 ") shouldBe Just(65535)

    portParser.eval("65536") shouldBe empty
  }

  test("parsing port ranges") {
    portRangeParser.eval("1024-1024") shouldBe Just((1024, 1024))
    portRangeParser.eval("1024-1025") shouldBe Just((1024, 1025))
    portRangeParser.eval("0-80 ") shouldBe Just((0, 80))

    portRangeParser.eval("0-65536") shouldBe empty
    portRangeParser.eval("0 -65535") shouldBe empty
    portRangeParser.eval("0 - 80") shouldBe empty
    portRangeParser.eval("1024-1023") shouldBe empty
  }

  test("parsing masks") {
    maskParser.eval("23asda") shouldBe Just(23)
    maskParser.eval("32 asd") shouldBe Just(32)
    maskParser.exec("32 asd") shouldBe Just(" asd")
    maskParser.eval("0") shouldBe Just(0)
    maskParser.exec("0") shouldBe Just("")
    maskParser.eval("111") shouldBe Just(11)
    maskParser.exec("111") shouldBe Just("1")

    maskParser.eval("01") shouldBe empty
    maskParser.eval("-1") shouldBe empty
    maskParser.eval("33") shouldBe empty
    maskParser.exec("33") shouldBe empty
  }

  test("parsing simple ips") {
    ipParser.eval("10.10.10.10") shouldBe Just(Ipv4(10, 10, 10, 10))
    ipParser.exec("10.10.10.10") shouldBe Just("")
    ipParser.eval("0.10.10.1") shouldBe Just(Ipv4(0, 10, 10, 1))
    ipParser.eval("0.0.0.0") shouldBe Just(Ipv4(0, 0, 0, 0))

    ipParser.eval("01.10.10.1") shouldBe empty
    ipParser.eval("001.10.10.1") shouldBe empty
    ipParser.eval("0001.10.10.1") shouldBe empty
    ipParser.eval("10..10.10") shouldBe empty
    ipParser.eval("10.10.10") shouldBe empty
    ipParser.eval("10.10.10.256") shouldBe empty
    ipParser.eval(".10.10.1") shouldBe empty
  }

  test("parsing ips with masks") {
    ipParser.eval("10.10.10.10/0") shouldBe Just(Ipv4(10, 10, 10, 10, Some(0)))
    ipParser.eval("0.0.0.10/24") shouldBe Just(Ipv4(0, 0, 0, 10, Some(24)))

    ipParser.eval("0.0.0.10/256") shouldBe Just(Ipv4(0, 0, 0, 10, Some(25)))
    ipParser.exec("0.0.0.10/256") shouldBe Just("6")
  }

  test("chain target parser simple") {
    chainTargetParser.eval("-j name") shouldBe
      Just(PlaceholderTarget("name"))
    chainTargetParser.eval(" --jump NamE") shouldBe
      Just(PlaceholderTarget("NamE"))
    chainTargetParser.eval(" --goto some$name") shouldBe
      Just(PlaceholderTarget("some$name", true))
    chainTargetParser.eval(" -g sOmeName") shouldBe
      Just(PlaceholderTarget("sOmeName", true))

    chainTargetParser.eval(" --jumpname") shouldBe empty
    chainTargetParser.eval(" --jum pname") shouldBe empty
    chainTargetParser.eval(" -jname") shouldBe empty
  }

  test("optionless target parser simple") {
    val only = new Target("ONLY") {}

    optionlessTargetParser(Map(("ONLY", only))).eval("-j ONLY") shouldBe
      Just(only)
    optionlessTargetParser(Map(("ONLY", only))).eval("--jump ONLY") shouldBe
      Just(only)

    optionlessTargetParser(Map(("ONLY", only))).eval("--goto ONLY") shouldBe
      empty
    optionlessTargetParser(Map(("ONLY", only))).eval("-g ONLY") shouldBe
      empty
    optionlessTargetParser(Map(("ONLY", only))).eval("--j umpONLY") shouldBe
      empty
    optionlessTargetParser(Map(("ONLY", only))).eval("-j OnLY") shouldBe
      empty
  }
}
