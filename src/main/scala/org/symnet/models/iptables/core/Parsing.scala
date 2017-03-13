// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet
package models.iptables
package core

import scalaz.{Maybe, MonadPlus, MonadState, NonEmptyList, StateT}

import types.net.{Ipv4, Port, PortRange}


/** The parsing context.
 *
 *  Example usage before initiating the parsing.
 *
 *  {{{
 *  implicit val context = new ParsingContext {
 *    matchExtensions  = List(...)
 *    targetExtensions = List(...)
 *  }
 *  }}}
 *
 *  If support for jump's/goto's to user defined chains, the predefined
 *  ChainTargetExtension should be added last in the target extensions list.
 */
abstract class ParsingContext {
  val matchExtensions:  List[MatchExtension]
  val targetExtensions: List[TargetExtension]
}

object Parsing {
  type Parser[A] = StateT[Maybe, String, A]

  val ParserMP = MonadPlus[Parser]
  import ParserMP.monadPlusSyntax._

  val ParserMS = MonadState[Parser, String]
  import ParserMS.{get, put}

  implicit class ParserOps[A](p: Parser[A]) {
    def <<|> =              p <+> (_: Parser[A])
    def <|>> = (_: Parser[A]) <+> p
  }

  /** This object includes several combinators used in parsing. */
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

    def oneOf[A](ps: Parser[A]*): Parser[A] = ps.reduce(_ <<|> _)
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

  def spacesParser: Parser[String] = many(parseCharIf(_.isWhitespace))

  def someSpacesParser: Parser[String] = some(parseCharIf(_.isWhitespace))

  def parseString(s: String): Parser[String] =
    if (s.isEmpty)
      pure("")
    else
      parseChar(s.head) >> parseString(s.tail) >>= (t => pure(s.head +: t))

  def stringParser: Parser[String] = some(parseCharIf(!_.isWhitespace))

  def digitParser: Parser[Int] = parseCharIf(_.isDigit).map(_.asDigit)


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
  /// Target, rule, chain and table parsers.
  ///

  def jumpOptionParser: Parser[String] =
    spacesParser >> oneOf(parseString("-j"), parseString("--jump"))

  def gotoOptionParser: Parser[String] =
    spacesParser >> oneOf(parseString("-g"), parseString("--goto"))

  /** Chain target parser.
   *
   *  This parser is used as the solution of last resort when matching targets
   *  in a rule, and the parsed target name should refer to the name of another
   *  chain.
   *
   *  This is ensured at a later stage, when the entire parsing is complete, to
   *  allow forward references.
   *
   *  NOTE: The rule parser (see above) containing it should be added last to
   *  the list of rule parsers as part of the parsing context if support for
   *  jumps to other chains is needed.
   *
   *  TODO(calincru): Add factory helper for this.
   */
  def chainTargetParser: Parser[Target] =
    for {
      jump       <- oneOf(jumpOptionParser, gotoOptionParser)
      targetName <- someSpacesParser >> stringParser
    } yield PlaceholderTarget(targetName, List("-g", "--goto").contains(jump))

  /** Helper implementation of a optionless target parser.
   *
   *  Other specialized target parsers can often be easily implemented by simply
   *  providing a mapping of target names and the actual target object from the
   *  iptables model.
   */
  def optionlessTargetParser(
      nameToTarget: Map[String, Target]): Parser[Target] = {
    for {
      _          <- jumpOptionParser
      targetName <- someSpacesParser >> stringParser
        if nameToTarget contains targetName
    } yield nameToTarget(targetName)
  }

  def ruleParser(implicit context: ParsingContext): Parser[Rule] = {
    val matchParsers  = context.matchExtensions.map(_.matchParsers).flatten
    val targetParsers = context.targetExtensions.map(_.targetParser)

    for {
      matches <- some(oneOf(matchParsers: _*))
      target  <- oneOf(targetParsers: _*)
    } yield Rule(matches, target)
  }

  def chainParser(implicit context: ParsingContext): Parser[Chain] =
    for {
      chainName   <- spacesParser >> parseChar('<') >> stringParser
      maybePolicy <- optional(parseChar(':') >> stringParser)
      _           <- parseChar('>')
      rules       <- many(ruleParser)
    } yield Chain(chainName, rules, Policy(maybePolicy getOrElse ""))

  def tableParser(implicit context: ParsingContext): Parser[Table] =
    for {
      tableName <- spacesParser >> stringParser
      chains    <- many(chainParser)
    } yield Table(tableName, chains)


  ///
  /// Object private functions.
  ///

  private def toInt(digits: List[Int]): Int = {
    val powers = Seq.iterate(1, digits.length)(_ * 10).reverse
    (digits, powers).zipped.map(_ * _).sum
  }

  private def digitsValid(digits: List[Int]): Boolean =
    !digits.isEmpty && !(digits.length >= 2 && digits(0) == 0)
}
