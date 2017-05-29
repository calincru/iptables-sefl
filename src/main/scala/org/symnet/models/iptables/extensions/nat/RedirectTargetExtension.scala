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
import org.change.v2.util.canonicalnames.{IPDst, TcpDst}

import types.net.{Ipv4, Port}

import core._
import extensions.filter.ProtocolMatch

object RedirectTargetExtension extends TargetExtension {
  val targetParser = RedirectTarget.parser
}

case class RedirectTarget(
    lowerPort: Option[Port],
    upperPort: Option[Port]) extends Target {
  type Self = RedirectTarget

  override protected def validateIf(context: ValidationContext): Boolean = {
    val table = context.table.get
    val chain = context.chain.get
    val rule = context.rule.get

    // Check the table/chain in which this target is valid.
    table.name == "nat" && (chain match {
      case _ @ BuiltinChain("PREROUTING", _, _) => true
      case _ @ BuiltinChain("OUTPUT", _, _) => true
      case _ @ UserChain(_, _) => true
      case _ => false
    }) &&
    // Check that 'tcp' or 'udp' is specified when given the port/port range.
    //
    // The existance of the lower port implies that '-p tcp/udp' must
    // have been specified.
    (lowerPort.isEmpty || ProtocolMatch.ruleMatchesTcpOrUdp(rule))
  }

  // NOTE: This is almost identical to DNAT; it differs only in that it uses the
  // ip address of the input port, instead of the one specified as part of the
  // '--to-destination' parameter.
  override def seflCode(options: SeflGenOptions): Instruction = {
    // Get the name of the metadata tags.
    val fromIp = virtdev.dnatFromIp(options.deviceId)
    val fromPort = virtdev.dnatFromPort(options.deviceId)
    val toIp = virtdev.dnatToIp(options.deviceId)
    val toPort = virtdev.dnatToPort(options.deviceId)

    InstructionBlock(
      // Save original addresses.
      Assign(fromIp, :@(IPDst)),
      Assign(fromPort, :@(TcpDst)),

      // Mangle IP address to the one of the interface this packet reached this
      // device on.
      Assign(IPDst, :@(virtdev.InputIpTag)),

      // Mangle TCP/UDP port address.
      Assign(TcpDst, SymbolicValue()),
      if (lowerPort.isDefined) {
        // If a port range was specified, use it.
        val (lower, upper) = (lowerPort.get, upperPort getOrElse lowerPort.get)

        Constrain(TcpDst, :&:(:>=:(ConstantValue(lower)),
                              :<=:(ConstantValue(upper))))
      } else {
        NoOp
      },

      // Save the new addresses.
      Assign(toIp, :@(IPDst)),
      Assign(toPort, :@(TcpDst)),

      // In the end, we accept the packet.
      Forward(options.acceptPort)
    )
  }
}

object RedirectTarget extends BaseParsers {
  import ParserMP.monadPlusSyntax._

  def parser: Parser[Target] =
    for {
      _ <- iptParsers.jumpOptionParser

      // Parse the actual target.
      targetName <- someSpacesParser >> identifierParser
        if targetName == "REDIRECT"

      // Parse the optional lower port.
      lowerPort <- optional(someSpacesParser >> parseString("--to-ports") >>
                            someSpacesParser >> portParser)
      upperPort <- conditional(optional(parseChar('-') >> portParser),
                               lowerPort.isDefined)
    } yield RedirectTarget(lowerPort, upperPort.flatten)
}
