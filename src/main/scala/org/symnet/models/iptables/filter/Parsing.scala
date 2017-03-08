// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet
package models.iptables
package filter

import core.{Match, MatchExtension, Parsing, Target, TargetExtension}
import types.net.Ipv4

import Parsing._
import Combinators._
import Parsing.ParserMP.monadPlusSyntax._

object FilteringExtension extends MatchExtension with TargetExtension {
  val matchParsers  = List(
    Impl.protocolMatchParser,
    Impl.srcIpMatchParser, Impl.dstIpMatchParser,
    Impl.inInterfaceMatchParser, Impl.outInterfaceMatchParser
  )
  val targetParser = Impl.targetParser

  object Impl {
    ///
    /// Protocol matcher.
    ///

    case class ProtocolMatch(
      val protocol: String,
      val negated: Boolean = false) extends Match(negated)

    def protocolMatchParser: Parser[Match] =
      for {
        _        <- spacesParser >> oneOf(parseString("-p"),
                                          parseString("--protocol"))
        neg      <- optional(someSpacesParser >> parseChar('!'))
        protocol <- someSpacesParser >> stringParser
      } yield ProtocolMatch(protocol, neg.isDefined)


    ///
    /// Source/Destination ip matchers.
    ///

    case class SourceMatch(
        val ip: Ipv4,
        val negated: Boolean = false) extends Match(negated)

    case class DestinationMatch(
        val ip: Ipv4,
        val negated: Boolean = false) extends Match(negated)

    def srcIpMatchParser: Parser[Match] =
      for {
        _   <- spacesParser >> oneOf(parseString("-s"),
                                     parseString("--source"),
                                     parseString("--src"))
        neg <- optional(someSpacesParser >> parseChar('!'))
        ip  <- someSpacesParser >> ipParser
      } yield SourceMatch(ip, neg.isDefined)

    def dstIpMatchParser: Parser[Match] =
      for {
        _   <- spacesParser >> oneOf(parseString("-d"),
                                     parseString("--destination"),
                                     parseString("--dst"))
        neg <- optional(someSpacesParser >> parseChar('!'))
        ip  <- someSpacesParser >> ipParser
      } yield DestinationMatch(ip, neg.isDefined)


    ///
    /// Input/Output interface matchers.
    ///

    case class InInterfaceMatch(
      val interface: String,
      val negated: Boolean = false) extends Match(negated)

    case class OutInterfaceMatch(
      val interface: String,
      val negated: Boolean = false) extends Match(negated)

    def inInterfaceMatchParser: Parser[Match] =
      for {
        _   <- spacesParser >> oneOf(parseString("-i"),
                                     parseString("--in-interface"))
        neg <- optional(someSpacesParser >> parseChar('!'))
        int <- someSpacesParser >> stringParser
      } yield InInterfaceMatch(int, neg.isDefined)

    def outInterfaceMatchParser: Parser[Match] =
      for {
        _   <- spacesParser >> oneOf(parseString("-o"),
                                     parseString("--out-interface"))
        neg <- optional(someSpacesParser >> parseChar('!'))
        int <- someSpacesParser >> stringParser
      } yield OutInterfaceMatch(int, neg.isDefined)


    ///
    /// The target parser.
    ///

    /** The base 'special' targets used in iptables. */
    case object AcceptTarget extends Target("ACCEPT")
    case object DropTarget   extends Target("DROP")
    case object ReturnTarget extends Target("RETURN")

    def targetParser: Parser[Target] =
      optionlessTargetParser(Map(("ACCEPT", AcceptTarget),
                                 ("DROP",   DropTarget),
                                 ("RETURN", ReturnTarget)))
  }
}
