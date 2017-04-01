// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet
package models.iptables.virtdev
package devices

class LocalProcess(
    name:     String,
    config:   Unit)
  extends RegularVirtualDevice[Unit](
    name,
    1, // input port
    0, // no output ports; it's a sink
    config) {

  override def portInstructions: Map[Port, Instruction] = Map.empty

  def inputPort: Port = inputPort(0)
}

case class LocalProcessBuilder(name: String)
  extends VirtualDeviceBuilder[LocalProcess](name) {

  override def build: LocalProcess = new LocalProcess(name, ())
}
