// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet
package models.iptables.virtdev
package devices

import org.change.v2.analysis.processingmodels.instructions.{:==:, Fork, Forward, Constrain, InstructionBlock}
import org.change.v2.analysis.expression.concrete.ConstantValue

trait OutputTagDispatcherConfig {
  val tagName: String

  // Maps value of the tag given by @tagName to the port id to forward packets
  // which have the tag set to that value.
  val tagValueToPortId: Map[Int, Int]
}

case class OutputTagDispatcher(
    name: String,
    outputPorts: Int,
    config: OutputTagDispatcherConfig)
  extends RegularVirtualDevice[OutputTagDispatcherConfig](
    name,
    1, // 1 input port
    outputPorts,
    config) {

  def inputPort: Port = inputPort(0)

  override def portInstructions: Map[Port, Instruction] = {
    val tag     = config.tagName
    val tagsMap = config.tagValueToPortId

    val portIdToInstr = (tagValue: Int, portId: Int) => InstructionBlock(
      Constrain(tag, :==:(ConstantValue(tagValue))),
      Forward(outputPort(portId))
    )

    Map(inputPort -> Fork(tagsMap.toList.map(
      { case (tagValue, portId) => portIdToInstr(tagValue, portId) }): _*))
  }
}

class OutputTagDispatcherBuilder(
    name: String,
    outputPorts: Int,
    tagsMap: Map[Int, Int],
    tag: Option[String] = None)
  extends VirtualDeviceBuilder[OutputTagDispatcher](name) {

  override def build: OutputTagDispatcher =
    OutputTagDispatcher(name, outputPorts, new OutputTagDispatcherConfig {
      val tagName = tag match {
        case Some(s) => s
        case _       => s"$name-otd"
      }

      val tagValueToPortId = tagsMap
    })
}
