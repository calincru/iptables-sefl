// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet
package models.iptables
package filter

import core.{Match, Parsing, TargetExtension, Target}
import types.net.{Ipv4, Port, PortRange}

import Parsing._
import Combinators._
import Parsing.ParserMP.monadPlusSyntax._

object SnatTargetExtension extends TargetExtension {
  val targetParser = Impl.targetParser

  object Impl {
    // TODO(calincru): Do something useful with this.
    case class SnatTarget(
        src:       Ipv4,
        portRange: Option[PortRange]) extends Target("SNAT")

    def targetParser: Parser[Target] =
      for {
        _ <- jumpOptionParser

        // Parse the actual target.
        targetName <- spacesParser >> stringParser if targetName == "SNAT"

        // Parse the mandatory '--to-source' target option.
        srcIp <- spacesParser >> ipParser

        // Parse the optional port range.
        maybePortRange <- optional(parseChar(':') >> portRangeParser)
      } yield SnatTarget(srcIp, maybePortRange)
  }
}

object DnatTargetExtension extends TargetExtension {
  val targetParser = Impl.targetParser

  object Impl {
    // TODO(calincru): Do something useful with this.
    case class DnatTarget(
        dst:       Ipv4,
        portRange: Option[PortRange]) extends Target("DNAT")

    def targetParser: Parser[Target] =
      for {
        _ <- jumpOptionParser

        // Parse the actual target.
        targetName <- spacesParser >> stringParser if targetName == "DNAT"

        // Parse the mandatory '--to-destination' target option.
        dstIp <- spacesParser >> ipParser

        // Parse the optional port range.
        maybePortRange <- optional(parseChar(':') >> portRangeParser)
      } yield DnatTarget(dstIp, maybePortRange)
  }
}

object MasqueradeTargetExtension extends TargetExtension {
  val targetParser = Impl.targetParser

  object Impl {
    // TODO(calincru): Do something useful with this.
    case class MasqueradeTarget(
        lowerPort: Port,
        upperPort: Option[Port]) extends Target("MASQUERADE")

    def targetParser: Parser[Target] =
      pure(MasqueradeTarget(1.toShort, Some(2.toShort)))
  }
}
