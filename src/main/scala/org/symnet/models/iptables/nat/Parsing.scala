// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet
package models.iptables
package filter

import core._
import types.net.{Ipv4, Port, PortRange}

import Parsing._
import Combinators._
import Parsing.ParserMP.monadPlusSyntax._

// TODO(calincru): Make sure that the IPs for snat and dnat are host IPs, not
// network IPs (no mask).

object SnatTargetExtension extends TargetExtension {
  val targetParser = Impl.targetParser

  object Impl {
    case class SnatTarget(
        lowerIp:   Ipv4,
        upperIp:   Option[Ipv4],
        portRange: Option[PortRange]) extends Target("SNAT") {

      override def isValid(
          rule: Rule,
          chain: Chain,
          table: Table): Boolean =
        table.name == "nat" && chain.name == "POSTROUTING"
    }

    def targetParser: Parser[Target] =
      for {
        _ <- jumpOptionParser

        // Parse the actual target.
        targetName <- someSpacesParser >> stringParser if targetName == "SNAT"

        // Parse the mandatory '--to-source' target option.
        _ <- someSpacesParser >> parseString("--to-source")
        lowerIp <- someSpacesParser >> ipParser

        // Parse the optional upper bound ip.
        upperIp <- optional(parseChar('-') >> ipParser)

        // Parse the optional port range.
        maybePortRange <- optional(parseChar(':') >> portRangeParser)
      } yield SnatTarget(lowerIp, upperIp, maybePortRange)
  }
}

object DnatTargetExtension extends TargetExtension {
  val targetParser = Impl.targetParser

  object Impl {
    case class DnatTarget(
        lowerIp:   Ipv4,
        upperIp:   Option[Ipv4],
        portRange: Option[PortRange]) extends Target("DNAT") {

      override def isValid(
          rule: Rule,
          chain: Chain,
          table: Table): Boolean =
        table.name == "nat" && (List("PREROUTING", "OUTPUT") contains chain.name)
    }

    def targetParser: Parser[Target] =
      for {
        _ <- jumpOptionParser

        // Parse the actual target.
        targetName <- someSpacesParser >> stringParser if targetName == "DNAT"

        // Parse the mandatory '--to-destination' target option.
        _ <- someSpacesParser >> parseString("--to-destination")
        lowerIp <- someSpacesParser >> ipParser

        // Parse the optional upper bound ip.
        upperIp <- optional(parseChar('-') >> ipParser)

        // Parse the optional port range.
        maybePortRange <- optional(parseChar(':') >> portRangeParser)
      } yield DnatTarget(lowerIp, upperIp, maybePortRange)
  }
}

object MasqueradeTargetExtension extends TargetExtension {
  val targetParser = Impl.targetParser

  object Impl {
    case class MasqueradeTarget(
        lowerPort: Option[Port],
        upperPort: Option[Port]) extends Target("MASQUERADE") {

      override def isValid(
          rule: Rule,
          chain: Chain,
          table: Table): Boolean =
        table.name == "nat" && chain.name == "POSTROUTING"
    }

    def targetParser: Parser[Target] =
      for {
        _ <- jumpOptionParser

        // Parse the actual  target
        targetName <- someSpacesParser >> stringParser
          if targetName == "MASQUERADE"

        // Parse the optional '--to-ports' target option
        // ([--to-ports port[-port]]).
        lowerPort <- optional(someSpacesParser >> parseString("--to-ports") >>
                              someSpacesParser >> portParser)

        // Try to parse the upper bound port only if the previous one succeeded.
        upperPort <-
          if (lowerPort.isDefined)
            optional(parseChar('-') >> portParser)
          else
            pure(None)
      } yield MasqueradeTarget(lowerPort, upperPort)
  }
}
