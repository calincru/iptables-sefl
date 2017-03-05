// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet
package models.iptables
package filter

import core._
import types.Net.Ipv4

object FilterRuleParsing extends RuleParser {
  val matchers = List(Impl.srcIpMatchParser, Impl.dstIpMatchParser)
  val targetParser = Impl.targetParser
  val targetOptionsParser = Impl.targetOptionsParser

  /** TODO */
  def newRule(
      matches: List[Match],
      target: Target,
      targetOptions: TargetOptions): Rule =
    new Rule(matches, target, targetOptions) {}

  private object Impl {
    import Parsing._
    import Parsing.ParserMP.monadPlusSyntax._

    case class SourceMatch(val ip: Ipv4) extends Match
    case class DestinationMatch(val ip: Ipv4) extends Match

    def srcIpMatchParser: Parser[Match] =
      for {
        _ <- spacesParser >> parseString("-s")
        ip <- spacesParser >> ipParser
      } yield SourceMatch(ip)

    def dstIpMatchParser: Parser[Match] =
      for {
        _ <- spacesParser >> parseString("-d")
        ip <- spacesParser >> ipParser
      } yield DestinationMatch(ip)

    /** The base 'special' targets used in iptables. */
    case object AcceptTarget extends Target("Accept", Nil, Some(Policy.Accept))
    case object DropTarget extends Target("Drop", Nil, Some(Policy.Drop))
    case object ReturnTarget extends Target("Return", Nil, Some(Policy.Return))

    def targetParser: Parser[Target] =
      for {
        _ <- spacesParser >> parseString("-j")
        target <- stringParser
      } yield (target.toLowerCase match {
        case "accept" => AcceptTarget
        case "drop"   => DropTarget
        case "return" => ReturnTarget
        case _        => Target.placeholder
      })

    def targetOptionsParser: Parser[TargetOptions] =
      pure(new TargetOptions {})
  }
}
