// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet
package models.iptables
package extensions.nat

import org.change.v2.analysis.expression.concrete.{ConstantValue, SymbolicValue}
import org.change.v2.analysis.expression.concrete.nonprimitive.:@
import org.change.v2.analysis.processingmodels.Instruction
import org.change.v2.analysis.processingmodels.instructions._
import org.change.v2.util.canonicalnames.{IPSrc, TcpSrc}

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

  // TODO: It is currently assumed that both TCP and UDP store the port address
  // at the same offset.
  // TODO: Parameterize the names of the tags on the device that does this.
  override def seflCode(options: SeflGenOptions): Instruction = {
    // If the upper bound is not given, we simply constrain on [lower, lower].
    val (lower, upper) = (lowerIp, upperIp getOrElse lowerIp)

    InstructionBlock(
      // Save original addresses.
      Assign(OriginalIP, :@(IPSrc)),
      Assign(OriginalPort, :@(TcpSrc)),

      // Mangle IP address.
      Assign(IPSrc, SymbolicValue()),
      Constrain(IPSrc, :&:(:>=:(ConstantValue(lower.host)),
                           :<=:(ConstantValue(upper.host)))),

      // Mangle TCP/UDP port address.
      Assign(TcpSrc, SymbolicValue()),
      if (portRange.isDefined) {
        // If a port range was specified, use it.
        val (lowerPort, upperPort) = portRange.get

        Constrain(IPSrc, :&:(:>=:(ConstantValue(lowerPort)),
                             :<=:(ConstantValue(upperPort))))
      } else {
        // Otherwise (from docs):
        //
        //    If no port range is specified, then source ports below 512 will be
        //    mapped to other ports below 512: those between 512 and 1023
        //    inclusive will be mapped to ports below 1024, and other ports will
        //    be mapped to 1024 or above. Where possible, no port alteration
        //    will occur.
        If(Constrain(OriginalPort, :<:(ConstantValue(512))),
           // then
           Constrain(TcpSrc, :<:(ConstantValue(512))),
           // else
           If(Constrain(OriginalPort, :<:(ConstantValue(1024))),
              // then
              Constrain(TcpSrc, :&:(:>=:(ConstantValue(512)),
                                    :<:(ConstantValue(1024)))),
              // else
              Constrain(TcpSrc, :>=:(ConstantValue(1024)))))
      },

      // Save the new addresses.
      Assign(NewIP, :@(IPSrc)),
      Assign(NewPort, :@(TcpSrc)),

      // In the end, we accept the packet.
      Forward(options.acceptPort)
    )
  }
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
