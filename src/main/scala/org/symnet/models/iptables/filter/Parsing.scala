// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet
package models.iptables
package filter

import core._
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

    case class ProtocolMatch(val protocol: String) extends Match {

      override def isValid(
          rule: Rule,
          chain: Chain,
          table: Table): Boolean =
        // Check if it is one of the 'named' protocols
        (List("tcp", "udp", "icmp", "all") contains protocol) ||
        // TODO(calincru): Check if it is a valid numeric protocol or a protocol
        // from /etc/protocols.
        false
    }

    def protocolMatchParser: Parser[Match] =
      for {
        _        <- spacesParser >> oneOf(parseString("-p"),
                                          parseString("--protocol"))
        neg      <- optional(someSpacesParser >> parseChar('!'))
        protocol <- someSpacesParser >> stringParser
      } yield Match.maybeNegated(ProtocolMatch(protocol), neg)


    ///
    /// Source/Destination ip matchers.
    ///

    case class SourceMatch(val ip: Ipv4) extends Match {

      override def isValid(
          rule: Rule,
          chain: Chain,
          table: Table): Boolean = true
    }

    case class DestinationMatch(val ip: Ipv4) extends Match {

      override def isValid(
          rule: Rule,
          chain: Chain,
          table: Table): Boolean = true
    }

    def srcIpMatchParser: Parser[Match] =
      for {
        _   <- spacesParser >> oneOf(parseString("-s"),
                                     parseString("--source"),
                                     parseString("--src"))
        neg <- optional(someSpacesParser >> parseChar('!'))
        ip  <- someSpacesParser >> ipParser
      } yield Match.maybeNegated(SourceMatch(ip), neg)

    def dstIpMatchParser: Parser[Match] =
      for {
        _   <- spacesParser >> oneOf(parseString("-d"),
                                     parseString("--destination"),
                                     parseString("--dst"))
        neg <- optional(someSpacesParser >> parseChar('!'))
        ip  <- someSpacesParser >> ipParser
      } yield Match.maybeNegated(DestinationMatch(ip), neg)


    ///
    /// Input/Output interface matchers.
    ///

    case class InInterfaceMatch(val interface: String) extends Match {

      override def isValid(
          rule: Rule,
          chain: Chain,
          table: Table): Boolean =
        chain match {
          case BuiltinChain(n, _, _) =>
            List("INPUT", "FORWARD", "PREROUTING") contains n
          case _ => false
        }
    }

    case class OutInterfaceMatch(val interface: String) extends Match {

      override def isValid(
          rule: Rule,
          chain: Chain,
          table: Table): Boolean =
        chain match {
          case BuiltinChain(n, _, _) =>
            List("FORWARD", "OUTPUT", "POSTROUTING") contains n
          case _ => false
        }
    }

    def inInterfaceMatchParser: Parser[Match] =
      for {
        _   <- spacesParser >> oneOf(parseString("-i"),
                                     parseString("--in-interface"))
        neg <- optional(someSpacesParser >> parseChar('!'))
        int <- someSpacesParser >> stringParser
      } yield Match.maybeNegated(InInterfaceMatch(int), neg)

    def outInterfaceMatchParser: Parser[Match] =
      for {
        _   <- spacesParser >> oneOf(parseString("-o"),
                                     parseString("--out-interface"))
        neg <- optional(someSpacesParser >> parseChar('!'))
        int <- someSpacesParser >> stringParser
      } yield Match.maybeNegated(OutInterfaceMatch(int), neg)


    ///
    /// The target parser.
    ///

    /// The base 'special' targets used in iptables.

    class FilterTarget(name: String) extends Target(name) {
      override def isValid(
          rule: Rule,
          chain: Chain,
          table: Table): Boolean =
        // The table should be 'filter' ...
        table.name == "filter" &&
        // ... and the chain, if it is a builtin one, should be one of the
        // following
        (chain match {
          case BuiltinChain(name, _, _) =>
            List("INPUT", "FORWARD", "OUTPUT") contains chain.name
          case _ /* UserChain */        => true
        })
    }

    case object AcceptTarget extends FilterTarget("ACCEPT")
    case object DropTarget   extends FilterTarget("DROP")
    case object ReturnTarget extends FilterTarget("RETURN")

    def targetParser: Parser[Target] =
      optionlessTargetParser(Map(("ACCEPT", AcceptTarget),
                                 ("DROP",   DropTarget),
                                 ("RETURN", ReturnTarget)))
  }
}
