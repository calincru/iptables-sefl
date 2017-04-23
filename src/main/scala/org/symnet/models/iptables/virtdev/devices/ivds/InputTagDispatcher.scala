// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet
package models.iptables.virtdev
package devices
package ivds

import org.change.v2.analysis.expression.concrete.ConstantValue
import org.change.v2.analysis.processingmodels.instructions.{:==:, Deallocate, Fork, Forward, Constrain, InstructionBlock}

case class InputTagDispatcher(
    name: String,
    outputPorts: Int)
  extends RegularVirtualDevice[Unit](
    name,
    1, // 1 input port
    outputPorts,
    ()) {

  require(outputPorts > 0)

  def inputPort: Port = inputPort(0)

  override def portInstructions: Map[Port, Instruction] = {
    val portIdToInstr = (i: Int) => InstructionBlock(
      // Make sure we only forward to the successor contiguous chain IVD of the
      // one that performed the original jump.
      Constrain(InputDispatchTag, :==:(ConstantValue(i))),

      // This pops the last value of this tag from the stack.
      Deallocate(InputDispatchTag),

      // Forward packets to the successor contiguous chain IVD of the one that
      // performed the original jump.
      Forward(outputPort(i))
    )

    // Forward to the port that matches the value of the input dispatch tag in
    // packet's metadata.
    Map(inputPort -> Fork((0 until outputPorts).map(portIdToInstr): _*))
  }
}
