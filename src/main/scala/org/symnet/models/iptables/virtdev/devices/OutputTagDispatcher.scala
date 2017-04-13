// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet
package models.iptables.virtdev
package devices

trait OutputTagDispatcherConfig {
  val tagName:     String
  val tagToPortId: Map[String, Int]
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

  // TODO
  override def portInstructions: Map[Port, Instruction] = Map.empty
}

class OutputTagDispatcherBuilder(
    name: String,
    outputPorts: Int,
    tagsMap: Map[String, Int],
    tag: Option[String] = None)
  extends VirtualDeviceBuilder[OutputTagDispatcher](name) {

  def build: OutputTagDispatcher =
    OutputTagDispatcher(name, outputPorts, new OutputTagDispatcherConfig {
      val tagName = tag match {
        case Some(s) => s
        case _       => s"$name-itd"
      }

      val tagToPortId = tagsMap
    })
}
