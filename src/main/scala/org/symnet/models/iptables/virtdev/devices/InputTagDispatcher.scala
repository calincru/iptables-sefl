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
    outputPorts: Int,
    tagName: String)
  extends RegularVirtualDevice[String](
    name,
    1, // 1 input port
    outputPorts,
    tagName) {

  def inputPort: Port = inputPort(0)

  override def portInstructions: Map[Port, Instruction] = {
    val portIdToInstr = (i: Int) => InstructionBlock(
      Constrain(tagName, :==:(ConstantValue(i))),
      Forward(outputPort(i))
    )

    // Forward to the port that matches the value of @tagName in packet's
    // metadata.
    Map(inputPort -> Fork((0 until outputPorts).map(portIdToInstr): _*))
  }
}

class InputTagDispatcherBuilder(
    name: String,
    outputPorts: Int,
    tagName: Option[String] = None)
  extends VirtualDeviceBuilder[InputTagDispatcher](name) {

  def build: InputTagDispatcher =
    InputTagDispatcher(name, outputPorts, tagName match {
      case Some(s) => s
      case _       => s"$name-itd"
    })
}
