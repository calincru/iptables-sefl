// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet
package models.iptables.virtdev
package devices
package ivds

import org.change.v2.analysis.expression.concrete.ConstantValue
import org.change.v2.analysis.processingmodels.instructions._

case class InputTagDispatcher(
    name: String,
    outputPorts: Int)
  extends IptablesVirtualDevice[Unit](name, 0, outputPorts, ()) {
  require(outputPorts > 0)

  override def ivdPortInstructions: Map[Port, Instruction] = {
    val portIdToInstr = (i: Int) => InstructionBlock(
      // Make sure we only forward to the successor contiguous chain IVD of the
      // one that performed the original jump.
      Constrain(InputDispatchTag, :==:(ConstantValue(i))),

      // This pops the last value of this tag from the stack.
      Deallocate(InputDispatchTag),

      // Forward packets to the successor contiguous chain IVD of the one that
      // performed the original jump.
      //
      // NOTE: For the special value `AcceptTagValue' we forward to the `accept'
      // port.
      Forward(if (i == AcceptTagValue) acceptPort else outputPort(i))
    )

    // Forward to the port that matches the value of the input dispatch tag in
    // packet's metadata.
    Map(inputPort -> {
      val allOutputPorts = (0 until outputPorts) :+ AcceptTagValue
      Fork(allOutputPorts.map(portIdToInstr): _*)
    })
  }
}
