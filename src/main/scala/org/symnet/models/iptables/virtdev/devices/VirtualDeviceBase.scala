// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet
package models.iptables.virtdev

package devices {

  abstract class VirtualDevice[+Config](
      val name:         String,
      val inputPorts:   Int,
      val outputPorts:  Int,
      config:       Config) {

    def inputPort(which: Int): Port = s"$name-in"
    def outputPort(which: Int): Port = s"$name-out"

    def portInstructions: Map[Port, Instruction]
  }

  abstract class RegularVirtualDevice[+Config](
      name:         String,
      inputPorts:   Int,
      outputPorts:  Int,
      config:       Config)
    extends VirtualDevice(name, inputPorts, outputPorts, config)

  abstract class CompositeVirtualDevice[+Config](
      name:         String,
      inputPorts:   Int,
      outputPorts:  Int,
      config:       Config)
    extends VirtualDevice[Config](name, inputPorts, outputPorts, config) {

    // Composite VDs don't have port instructions themselves, but they link
    // together VDs which do.
    def portInstructions: Map[Port, Instruction] = Map.empty
  }

  abstract class VirtualDeviceBuilder[T <: VirtualDevice[_]](
      deviceName: String) {
    def build: T
  }
}
