// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet
package models.iptables.virtdev
package devices

import org.change.v2.analysis.expression.concrete.ConstantValue
import org.change.v2.analysis.processingmodels.instructions.{Assign, Allocate, InstructionBlock}

case class InputPortSetter(
    name:   String,
    portId: Int)
  extends RegularVirtualDevice[Int](
    name,
      // single input port
    1,
      // single output port
    1,
    portId) {

  def inputPort: Port  = inputPort(0)
  def outputPort: Port = outputPort(0)

  override def portInstructions: Map[Port, Instruction] =
    Map(inputPort ->
        InstructionBlock(
          Allocate(InputPortTag),
          Assign(InputPortTag, ConstantValue(portId))))
}
