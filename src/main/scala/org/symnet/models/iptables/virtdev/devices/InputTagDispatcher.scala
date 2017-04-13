// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet
package models.iptables.virtdev
package devices

import org.change.v2.analysis.processingmodels.instructions.{:==:, Fork, Forward, Constrain, InstructionBlock}
import org.change.v2.analysis.expression.concrete.ConstantValue

case class InputTagDispatcher(
    name: String,
    outputPorts: Int)
  extends RegularVirtualDevice[Unit](
    name,
    1, // 1 input port
    outputPorts,
    ()) {

  def inputPort: Port = inputPort(0)

  override def portInstructions: Map[Port, Instruction] = {
    val portIdToInstr = (i: Int) => InstructionBlock(
      Constrain(IN_DISPATCH_TAG_NAME, :==:(ConstantValue(i))),
      Forward(outputPort(i))
    )

    // Forward to the port that matches the value of IN_DISPATCH_TAG_NAME in
    // packet's metadata.
    Map(inputPort -> Fork((0 until outputPorts).map(portIdToInstr): _*))
  }
}
