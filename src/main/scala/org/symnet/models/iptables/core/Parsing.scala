// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet
package models.iptables
package core

import scalaz.{Maybe, MonadPlus, MonadState, StateT}

import types.Net.Ipv4

abstract class RuleParser {
  import Parsing.Parser

  val matchers: List[Parser[Match]]
  val targetParser: Parser[Target]
  val targetOptionsParser: Parser[TargetOptions]

  def newRule(
    matches: List[Match],
    target: Target,
    targetOptions: TargetOptions): Rule
}

/** The parsing context.
 *
 * Example usage before initiating the parsing.
 *
 *  {{{
 *  implicit val context = new ParsingContext {
 *    ruleParsers = List(...)
 *  }
 *  }}}
 */
trait ParsingContext {
  val ruleParsers: List[RuleParser]
}

object Parsing {
  type Parser[A] = StateT[Maybe, String, A]

  val ParserMP = MonadPlus[Parser]
  import ParserMP.monadPlusSyntax._

  private val ParserMS = MonadState[Parser, String]
  import ParserMS.{get, put}

  implicit class ParserOps[A](p: Parser[A]) {
    def <<|> =              p <+> (_: Parser[A])
    def <|>> = (_: Parser[A]) <+> p
  }

  /** This object includes several combinators used in parsing.
   *
   *  TODO: Doc
   */
  object Combinators {
    def optional[A](p: Parser[A]): Parser[Option[A]] =
      (p >>= (x => pure(Option(x)))) <<|> pure(None)

    def many[A](p: Parser[A]): Parser[List[A]] = some(p) <<|> pure(Nil)

    def some[A](p: Parser[A]): Parser[List[A]] =
      for {
        x <- p
        y <- many(p)
      } yield (x +: y)

    def atMost[A](n: Int, p: Parser[A]): Parser[List[A]] =
      if (n <= 0)
        pure(Nil)
      else
        optional(p) >>= (_ match {
          case Some(x) => atMost(n - 1, p) >>= (xs => pure(x :: xs))
          case None    => pure(Nil)
        })
  }
  import Combinators._

  ///
  /// Basic parsers.
  ///

  def parseCharIf(f: Char => Boolean): Parser[Char] =
    for {
      input <- get if !input.isEmpty && f(input.head)
      _     <- put(input.tail)
    } yield input.head

  def parseChar(c: Char): Parser[Char] = parseCharIf(_ == c)

  def spacesParser: Parser[String] = many(parseCharIf(_.isSpaceChar))

  def parseString(s: String): Parser[String] =
    if (s.isEmpty)
      pure("")
    else
      parseChar(s.head) >> parseString(s.tail) >>= (t => pure(s.head +: t))

  def stringParser: Parser[String] = some(parseCharIf {!_.isSpaceChar})

  def digitParser: Parser[Int] = parseCharIf(_.isDigit).map(_.asDigit)

  def byteParser: Parser[Int] =
    for {
      digits <- atMost(3, digitParser) if digitsValid(digits)
      byte = toByte(digits) if byte <= 255
    } yield byte

  def maskParser: Parser[Int] =
    for {
      digits <- atMost(2, digitParser) if digitsValid(digits)
      mask = toByte(digits) if mask <= 32
    } yield mask

  def ipParser: Parser[Ipv4] =
    for {
      b0 <- byteParser
      b1 <- parseChar('.') >> byteParser
      b2 <- parseChar('.') >> byteParser
      b3 <- parseChar('.') >> byteParser
      optionalMask <- optional(parseChar('/') >> maskParser)
    } yield Ipv4(b0, b1, b2, b3, optionalMask)


  ///
  /// Rule, chain and table (TODO) parsers.
  ///

  def ruleParser(rp: RuleParser): Parser[Rule] =
    for {
      matches <- some(rp.matchers.reduce(_ <<|> _))
      target  <- rp.targetParser
      targetOptions <- rp.targetOptionsParser
    } yield rp.newRule(matches, target, targetOptions)

  def chainParser(implicit context: ParsingContext): Parser[Chain] =
    for {
      chainName <- spacesParser >> parseChar('<') >> stringParser
      maybePolicy <- optional(parseChar(':') >> stringParser)
      _ <- parseChar('>')
      rules <- context.ruleParsers.map(x => many(ruleParser(x))).reduce(_ <<|> _)
    } yield Chain(chainName, rules, Policy(maybePolicy getOrElse ""))


  ///
  /// Object private functions.
  ///

  private def toByte(digits: List[Int]): Int = {
    val powers = Seq.iterate(1, digits.length)(_ * 10).reverse
    (digits, powers).zipped.map(_ * _).sum
  }

  private def digitsValid(digits: List[Int]): Boolean =
    !digits.isEmpty && !(digits.length >= 2 && digits(0) == 0)
}
