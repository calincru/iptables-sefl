// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet
package models.iptables.virtdev
package devices

import org.change.v2.abstractnet.generic.{Port => SPort}
import org.change.v2.abstractnet.click.sefl.LinearIPLookupElementBuilder

// NOTE: This is just a wrapper over 'LinearIPLookup' from the click models.
class ForwardingDecision(
      name:         String,
      outputPorts:  Int,
      routingTable: List[String])
  extends RegularVirtualDevice[List[String]](
      name,
      1, // input port
      outputPorts,
      routingTable) {

  def inputPort: Port = inputPort(0)

  override def portInstructions: Map[Port, Instruction] =
    linearIPLookup.instructions

  // TODO: For now it uses a linear ip lookup.  Change it to the optimal one,
  // as described in the paper.
  private val linearIPLookup = {
    val builder = new LinearIPLookupElementBuilder(name, "LinearIPLookup")

    // one unique input port
    builder.addInputPort(SPort())

    // set output ports
    for (i <- 0 until outputPorts)
      builder.addOutputPort(SPort())

    // pass it the routing table
    for (prefix <- routingTable)
      builder.handleConfigParameter(prefix)

    builder.buildElement
  }
}
