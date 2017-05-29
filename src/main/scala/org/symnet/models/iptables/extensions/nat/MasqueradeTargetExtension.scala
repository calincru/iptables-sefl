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

import types.net.{Ipv4, Port}

import core._
import extensions.filter.ProtocolMatch

object MasqueradeTargetExtension extends TargetExtension {
  val targetParser = MasqueradeTarget.parser
}

case class MasqueradeTarget(
    lowerPort: Option[Port],
    upperPort: Option[Port]) extends Target {
  type Self = MasqueradeTarget

  /** This target is only valid in the 'nat' table, in the 'POSTROUTING'
   *  chain.
   *
   *  The '--to-ports' option is only valid if the rule also specifies
   *  '-p tcp' or '-p udp'.
   */
  override protected def validateIf(context: ValidationContext): Boolean = {
    val chain = context.chain.get
    val table = context.table.get
    val rule = context.rule.get

    // Check the table/chain in which this target is valid.
    table.name == "nat" && (chain match {
      case _ @ BuiltinChain("POSTROUTING", _, _) => true
      case _ @ UserChain(_, _) => true
      case _ => false
    }) &&
    // The existance of the upper port implies the existance of the lower
    // one.
    //
    //      upperPort -> lowerPort <=> !upperPort or lowerPort
    //
    (upperPort.isEmpty || lowerPort.isDefined) &&
    // Check that 'tcp' or 'udp' is specified when either of the lower/upper
    // ports are given.
    //
    // The existance of any of the lower/upper ports implies that '-p
    // tcp/udp' must have been specified.
    //
    //      lowerPort or upperPort -> tcp/udp
    // but  upperPort -> lowerPort =>
    // =>   lowerPort -> tcp/udp  <=> !lowerPort or tcp/udp
    //
    (lowerPort.isEmpty || ProtocolMatch.ruleMatchesTcpOrUdp(rule))
  }

  // NOTE: This is almost identical to SNAT; it differs only in that it uses the
  // saved ip of the output port, instead of a specified port (range).
  override def seflCode(options: SeflGenOptions): Instruction = {
    // Get the name of the metadata tags.
    val fromIp = virtdev.snatFromIp(options.deviceId)
    val fromPort = virtdev.snatFromPort(options.deviceId)
    val toIp = virtdev.snatToIp(options.deviceId)
    val toPort = virtdev.snatToPort(options.deviceId)

    InstructionBlock(
      // Save original addresses.
      Assign(fromIp, :@(IPSrc)),
      Assign(fromPort, :@(TcpSrc)),

      // Mangle IP address to the one of the interface this packet is going to
      // leave the device.
      Assign(IPSrc, :@(virtdev.OutputIpTag)),

      // Mangle TCP/UDP port address.
      Assign(TcpSrc, SymbolicValue()),
      if (lowerPort.isDefined) {
        // Get the port range to constrain to.
        val (lower, upper) = (lowerPort.get, upperPort.getOrElse(lowerPort.get))

        Constrain(TcpSrc, :&:(:>=:(ConstantValue(lower)),
                              :<=:(ConstantValue(upper))))
      } else {
        // Otherwise (from docs):
        //
        //    If no port range is specified, then source ports below 512 will be
        //    mapped to other ports below 512: those between 512 and 1023
        //    inclusive will be mapped to ports below 1024, and other ports will
        //    be mapped to 1024 or above. Where possible, no port alteration
        //    will occur.
        If(Constrain(fromPort, :<:(ConstantValue(512))),
           // then
           Constrain(TcpSrc, :<:(ConstantValue(512))),
           // else
           If(Constrain(fromPort, :<:(ConstantValue(1024))),
              // then
              Constrain(TcpSrc, :&:(:>=:(ConstantValue(512)),
                                    :<:(ConstantValue(1024)))),
              // else
              Constrain(TcpSrc, :>=:(ConstantValue(1024)))))
      },

      // Save the new addresses.
      Assign(toIp, :@(IPSrc)),
      Assign(toPort, :@(TcpSrc)),

      // In the end, we accept the packet.
      Forward(options.acceptPort)
    )
  }
}

object MasqueradeTarget extends BaseParsers {
  import ParserMP.monadPlusSyntax._

  def parser: Parser[Target] =
    for {
      _ <- iptParsers.jumpOptionParser

      // Parse the actual  target
      targetName <- someSpacesParser >> identifierParser
        if targetName == "MASQUERADE"

      // Parse the optional '--to-ports' target option
      // ([--to-ports port[-port]]).
      lowerPort <- optional(someSpacesParser >> parseString("--to-ports") >>
                            someSpacesParser >> portParser)

      // Try to parse the upper bound port only if the previous one succeeded.
      upperPort <- conditional(optional(parseChar('-') >> portParser),
                               lowerPort.isDefined)
    } yield MasqueradeTarget(lowerPort, upperPort.flatten)
}
