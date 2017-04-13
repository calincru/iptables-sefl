// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet
package models.iptables.virtdev
package devices

import org.change.v2.analysis.processingmodels.instructions.{:==:, Fork, Forward, Constrain, InstructionBlock}
import org.change.v2.analysis.expression.concrete.ConstantValue

/** 'tagValues' is the list of values expected for the OUT_DISPATCH_TAG_NAME.
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

  def outputPorts: Int = tagValues.length

  def inputPort: Port = inputPort(0)

  override def portInstructions: Map[Port, Instruction] = {
    val portIdToInstr = (tagValue: Int, portId: Int) => InstructionBlock(
      Constrain(OUT_DISPATCH_TAG_NAME, :==:(ConstantValue(tagValue))),
      Forward(outputPort(portId))
    )

    Map(inputPort -> Fork(tagValues.zipWithIndex.map(
      { case (tagValue, portId) => portIdToInstr(tagValue, portId) }): _*))
  }
}
