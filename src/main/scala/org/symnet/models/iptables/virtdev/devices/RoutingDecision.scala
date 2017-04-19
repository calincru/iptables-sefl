// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet
package models.iptables.virtdev
package devices

import org.change.v2.analysis.expression.concrete.ConstantValue
import org.change.v2.analysis.processingmodels.instructions._
import org.change.v2.util.canonicalnames.IPDst

import types.net.Ipv4

trait RoutingDecisionConfig {
  val localIps:     List[Ipv4]
  val routingTable: RoutingTable
}

case class RoutingDecision(
    name:   String,
    config: RoutingDecisionConfig)
  extends RegularVirtualDevice[RoutingDecisionConfig](
    name,
      // single input port
    1,
      // 2 output ports:
      //  * 0 - to local process
      //  * 1 - to the next step
    2,
    config) {

  def inputPort: Port = inputPort(0)

  def localOutputPort: Port = outputPort(0)
  def fwdOutputPort:   Port = outputPort(1)

  override def portInstructions: Map[Port, Instruction] = {
    val fwdLookup = buildIpLookup(
      // The ordered list of routing table entries,
      config.routingTable,

      // The default instruction in case no prefix matches.
      Fail(s"No route found by $name"),

      // The function that tells how to use the port to generate a 'then'
      // instruction, when a prefix matches.
      port => InstructionBlock(
        // Store the output interface this packet will be sent through.
        Allocate(OutputPortTag),
        Assign(OutputPortTag, ConstantValue(port)),

        // Forward it to the next step in router's logic.
        Forward(fwdOutputPort)))

    // Build a 'routing table' (list of prefixes and output ports) which knows
    // how to identify if the packet is headed to one of router's local IPs.
    //
    // NOTE: The port ID is not important here, as we already know the name of
    // the port we are forwarding this packet to (see below); 0 has been chosen
    // as it is the ID of the local output port.
    val localRoutingTable = config.localIps.map((_, 0))

    // Finally, assign the input port the responsibility to do the IP lookup, by
    // first checking local IPs and falling back to the forwarding table.
    Map(inputPort ->
        buildIpLookup(
          localRoutingTable,
          fwdLookup,
          _ => Forward(localOutputPort)))
  }

  private def buildIpLookup(
      routingTable: RoutingTable,
      defaultInstr: Instruction,
      getThenInstr: (Int) => Instruction): Instruction =
    routingTable.foldRight(defaultInstr)((rtEntry, acc) => {
      val (prefix, port) = rtEntry
      val (lower, upper) = prefix.toHostRange

      If(Constrain(IPDst, :&:(:>=:(ConstantValue(lower.host)),
                              :<=:(ConstantValue(upper.host)))),
         getThenInstr(port),
         acc)
    })
}
