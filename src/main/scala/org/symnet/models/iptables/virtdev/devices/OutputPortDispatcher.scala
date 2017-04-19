// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet
package models.iptables.virtdev
package devices

import org.change.v2.analysis.expression.concrete.ConstantValue
import org.change.v2.analysis.processingmodels.instructions.{:==:, Constrain, Fork, Forward, InstructionBlock}

case class OutputPortDispatcher(
    name:        String,
    outputPorts: Int)
  extends RegularVirtualDevice[Unit](
    name,
      // single input port
    1,
    outputPorts,
    ()) {

  def inputPort: Port  = inputPort(0)

  override def portInstructions: Map[Port, Instruction] =
    Map(inputPort -> Fork((0 until outputPorts).map(i => InstructionBlock(
      Constrain(OutputPortTag, :==:(ConstantValue(i))),
      Forward(outputPort(i)))): _*))
}
