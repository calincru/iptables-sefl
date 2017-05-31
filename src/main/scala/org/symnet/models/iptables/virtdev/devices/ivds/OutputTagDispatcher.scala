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

/** 'tagValues' is the list of values expected for the OutputDispatchTag.
 *
 *  NOTE: Packets are forwarded to the output ports according to the order in
 *  this list (aka order matters).
 */
case class OutputTagDispatcher(
    name:        String,
    tagValues:   List[Int])
  extends RegularVirtualDevice[List[Int]](
    name,
      // sole input port
    1,
      // the number of output ports is given by the number of tag values to
      // match
    tagValues.length,
    tagValues) {

  require(outputPorts >= 0)

  def inputPort: Port = inputPort(0)

  def outputPorts: Int = tagValues.length

  override def portInstructions: Map[Port, Instruction] = {
    val portIdToInstr = (tagValue: Int, portId: Int) => InstructionBlock(
      // Make sure we only forward to the chain IVD that performed the jump to
      // this one.
      Constrain(OutputDispatchTag, :==:(ConstantValue(tagValue))),

      // This pops the last value of this tag from the stack.
      //
      // We are guaranteed this makes sense because the only way we might hit a
      // 'RETURN' is if we have jumped to the chain IVD this tag dispatcher is
      // part of.
      Deallocate(OutputDispatchTag),

      // Forward packets to the chain IVD that performed the jump to this one.
      Forward(outputPort(portId))
    )

    Map(inputPort -> Fork(tagValues.zipWithIndex.map(
      { case (tagValue, portId) => portIdToInstr(tagValue, portId) }): _*))
  }
}
