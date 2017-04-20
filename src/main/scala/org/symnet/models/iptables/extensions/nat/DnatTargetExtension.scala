// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet
package models.iptables
package extensions.nat

import org.change.v2.analysis.processingmodels.Instruction
import org.change.v2.analysis.processingmodels.instructions._

import types.net.{Ipv4, PortRange}

import core._
import extensions.filter.ProtocolMatch

case class DnatTarget(
    lowerIp:   Ipv4,
    upperIp:   Option[Ipv4],
    portRange: Option[PortRange]) extends Target {

  override protected def validateIf(
      rule: Rule,
      chain: Chain,
      table: Table): Boolean =
    // Check the table/chain in which this target is valid.
    table.name == "nat" &&
      (List("PREROUTING", "OUTPUT") contains chain.name) &&
    // Check that 'tcp' or 'udp' is specified when given the port range.
    //
    // The existance of the port range implies that '-p tcp/udp' must
    // have been specified.
    (portRange.isEmpty || ProtocolMatch.ruleMatchesTcpOrUdp(rule))

  override def seflCode(options: SeflGenOptions): Instruction = {
    // If the upper bound is not given, we simply constrain on [lower, lower].
    val (lower, upper) = (lowerIp, upperIp getOrElse lowerIp)

    InstructionBlock(
      // TODO: Do DNAT.

      // In the end, we accept the packet.
      Forward(options.acceptPort)
    )
  }
}

object DnatTarget extends BaseParsers {
  import ParserMP.monadPlusSyntax._

  def parser: Parser[Target] =
    for {
      _ <- iptParsers.jumpOptionParser

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

object DnatTargetExtension extends TargetExtension {
  val targetParser = DnatTarget.parser
}
