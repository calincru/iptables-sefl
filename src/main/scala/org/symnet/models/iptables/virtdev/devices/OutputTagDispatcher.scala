// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet
package models.iptables.virtdev
package devices

trait OutputTagDispatcherConfig {
  val tagName: String
  // TODO: un map de la tag la portul pe care sa faca forward
}

case class OutputTagDispatcher(
    name: String,
    outputPorts: Int,
    tagName: String)
  extends RegularVirtualDevice[String](
    name,
    1, // 1 input port
    outputPorts,
    tagName) {

  def inputPort: Port = inputPort(0)

  override def portInstructions: Map[Port, Instruction] = Map.empty
}
