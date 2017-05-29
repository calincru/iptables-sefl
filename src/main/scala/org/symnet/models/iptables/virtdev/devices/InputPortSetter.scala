// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet
package models.iptables.virtdev
package devices

// 3rd-party
// -> Symnet
import org.change.v2.analysis.expression.concrete.ConstantValue
import org.change.v2.analysis.processingmodels.instructions.{Assign, Forward, InstructionBlock}

// project
import types.net.Ipv4

trait InputPortSetterConfig {
  val portId: Int
  val portIp: Ipv4
}

class InputPortSetter(
    name:   String,
    config: InputPortSetterConfig)
  extends RegularVirtualDevice[InputPortSetterConfig](
    name,
      // single input port
    1,
      // single output port
    1,
    config) {

  def inputPort: Port  = inputPort(0)
  def outputPort: Port = outputPort(0)

  override def portInstructions: Map[Port, Instruction] =
    Map(inputPort -> InstructionBlock(
      Assign(InputPortTag, ConstantValue(config.portId)),
      Assign(InputIpTag, ConstantValue(config.portIp.host)),
      Forward(outputPort)
    ))
}
