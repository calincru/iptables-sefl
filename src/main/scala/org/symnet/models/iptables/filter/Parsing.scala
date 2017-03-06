// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet
package models.iptables
package filter

import core.{Match, Parsing, RuleParser, Target}
import types.Net.Ipv4

object FilterRuleParsing extends RuleParser {
  val matchParsers = List(Impl.srcIpMatchParser, Impl.dstIpMatchParser)
  val targetParsers = List(Impl.targetParser)

  private object Impl {
    import Parsing._
    import Parsing.ParserMP.monadPlusSyntax._

    case class SourceMatch(val ip: Ipv4) extends Match
    case class DestinationMatch(val ip: Ipv4) extends Match

    def srcIpMatchParser: Parser[Match] =
      for {
        _  <- spacesParser >> parseString("-s")
        ip <- spacesParser >> ipParser
      } yield SourceMatch(ip)

    def dstIpMatchParser: Parser[Match] =
      for {
        _  <- spacesParser >> parseString("-d")
        ip <- spacesParser >> ipParser
      } yield DestinationMatch(ip)

    /** The base 'special' targets used in iptables. */
    case object AcceptTarget extends Target("Accept")
    case object DropTarget   extends Target("Drop")
    case object ReturnTarget extends Target("Return")

    def targetParser: Parser[Target] = {
      val targets = Map(("accept", AcceptTarget),
                        ("drop",   DropTarget),
                        ("return", ReturnTarget))
      for {
        _      <- spacesParser >> parseString("-j")
        target <- stringParser.map(_.toLowerCase) if targets contains target
      } yield targets(target)
    }
  }
}
