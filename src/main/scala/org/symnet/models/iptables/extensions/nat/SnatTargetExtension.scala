// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet
package models.iptables
package extensions.nat

import org.change.v2.analysis.processingmodels.Instruction

import types.net.{Ipv4, PortRange}

import core._
import extensions.filter.ProtocolMatch

case class SnatTarget(
    lowerIp:   Ipv4,
    upperIp:   Option[Ipv4],
    portRange: Option[PortRange]) extends Target {

  override protected def validateIf(
      rule: Rule,
      chain: Chain,
      table: Table): Boolean =
    // Check the table/chain in which this target is valid.
    table.name == "nat" && chain.name == "POSTROUTING" &&
    // Check that 'tcp' or 'udp' is specified when given the port range.
    //
    // The existance of the port range implies that '-p tcp/udp' must
    // have been specified.
    (portRange.isEmpty || ProtocolMatch.ruleMatchesTcpOrUdp(rule))

  // TODO
  def seflCode(options: SeflGenOptions): Instruction = null
}

object SnatTarget extends BaseParsers {
  import ParserMP.monadPlusSyntax._

  def parser: Parser[Target] =
    for {
      _ <- iptParsers.jumpOptionParser

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

object SnatTargetExtension extends TargetExtension {
  val targetParser = SnatTarget.parser
}
