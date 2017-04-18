// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet
package models.iptables.virtdev
package devices
package ivds

import org.change.v2.analysis.expression.concrete.ConstantValue
import org.change.v2.analysis.processingmodels.instructions.{Assign, Allocate, Forward, InstructionBlock}

case class ChainIVDInitializer(name: String)
  extends RegularVirtualDevice[Unit](
    name,
    1, // one input port
    1, // one output port
    ()) {

  def inputPort:  Port = inputPort(0)
  def outputPort: Port = outputPort(0)

  override def portInstructions: Map[Port, Instruction] = List(
    // Initialize the input dispatch tag: allocate a new one and initialize it
    // to zero.
    Map(inputPort -> InstructionBlock(
      Allocate(InputDispatchTag),
      Assign(InputDispatchTag, ConstantValue(0)),
      Forward(outputPort)))

  ).flatten.toMap
}
