// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet
package models.iptables
package core

// scala
import scala.util.Try

// 3rd-party
// -> scalaz
import scalaz.{Maybe, MonadPlus, MonadState, NonEmptyList, StateT}

// project
import types.net.{Ipv4, Port, PortRange}

trait BaseParsers {
  type Parser[A] = StateT[Maybe, String, A]

  protected val ParserMP = MonadPlus[Parser]
  import ParserMP.monadPlusSyntax._

  private val ParserMS = MonadState[Parser, String]
  import ParserMS.{get, put}

  implicit class ParserOps[A](p: Parser[A]) {
    def <<|> =              p <+> (_: Parser[A])
    def <|>> = (_: Parser[A]) <+> p
  }

  /** This object includes several combinators used in parsing. */
  def optional[A](p: Parser[A]): Parser[Option[A]] =
    (p >>= (x => pure(Option(x)))) <<|> pure(None)

  def conditional[A](p: Parser[A], condition: Boolean): Parser[Option[A]] =
    if (condition) (p >>= (x => pure(Option(x)))) else pure(None)

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

  def oneOf[A](ps: Parser[A]*): Parser[A] = ps.reduce(_ <<|> _)

  ///
  /// Basic parsers.
  ///

  def parseCharIf(f: Char => Boolean): Parser[Char] =
    for {
      input <- get if !input.isEmpty && f(input.head)
      _     <- put(input.tail)
    } yield input.head

  def parseUntil(c: Char): Parser[String] =
    many(parseCharIf(_ != c))

  def parseChar(c: Char): Parser[Char] = parseCharIf(_ == c)

  def spacesParser: Parser[String] = many(parseCharIf(_.isWhitespace))

  def someSpacesParser: Parser[String] = some(parseCharIf(_.isWhitespace))

  def parseString(s: String): Parser[String] =
    if (s.isEmpty)
      pure("")
    else
      parseChar(s.head) >> parseString(s.tail) >>= (t => pure(s.head +: t))

  // TODO: Make sure this conforms to the real implementation.
  def identifierParser: Parser[String] =
    some(parseCharIf(c => c.isLetterOrDigit || c == '_' || c == '-'))

  def digitParser: Parser[Int] = parseCharIf(_.isDigit).map(_.asDigit)

  def hexLongParser: Parser[Long] =
    for {
      maybeNr <- parseString("0x") >> some(parseCharIf(_.isDigit)).map(
        x => Try(x.mkString.toLong).toOption) if maybeNr.isDefined
    } yield maybeNr.get


  ///
  /// Common parsers provided here to avoid duplicated code.
  ///

  def byteParser: Parser[Int] =
    for {
      digits <- atMost(3, digitParser) if digitsValid(digits)
      byte = toInt(digits) if byte <= 255
    } yield byte

  def portParser: Parser[Port] =
    for {
      digits <- atMost(5, digitParser) if digitsValid(digits)
      port = toInt(digits) if port < (1 << 16)
    } yield port

  def portRangeParser: Parser[PortRange] =
    for {
      lhs <- portParser
      _   <- parseChar('-')
      rhs <- portParser if rhs >= lhs
    } yield (lhs, rhs)

  def maskParser: Parser[Int] =
    for {
      digits <- atMost(2, digitParser) if digitsValid(digits)
      mask = toInt(digits) if mask <= 32
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
  /// Private functions.
  ///

  private def toInt(digits: List[Int]): Int = {
    val powers = Seq.iterate(1, digits.length)(_ * 10).reverse
    (digits, powers).zipped.map(_ * _).sum
  }

  private def digitsValid(digits: List[Int]): Boolean =
    !digits.isEmpty && !(digits.length >= 2 && digits(0) == 0)
}
