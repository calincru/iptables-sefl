// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet
package models.iptables.virtdev

package devices {
  abstract class VirtualDevice[+Config](
      name:         String,
      inputPorts:   Int,
      outputPorts:  Int,
      config:       Config) {

    def inputPort(which: Int):  Port = {
      assert(which < inputPorts)
      s"$name-in-$which"
    }
    def outputPort(which: Int): Port = {
      assert(which < outputPorts)
      s"$name-out-$which"
    }

    def portInstructions: Map[Port, Instruction]
    def links:            Map[Port, Port]
  }

  abstract class RegularVirtualDevice[+Config](
      name:         String,
      inputPorts:   Int,
      outputPorts:  Int,
      config:       Config)
    extends VirtualDevice(name, inputPorts, outputPorts, config) {

    // It is generally the case that regular VDs don't have links, otherwise
    // they would be composite VDs.
    //
    // However, if that's not the case, this method can still be overridden,
    // this is just the default.
    override def links: Map[Port, Port] = Map.empty
  }

  abstract class CompositeVirtualDevice[+Config](
      name:         String,
      inputPorts:   Int,
      outputPorts:  Int,
      config:       Config)
    extends VirtualDevice[Config](name, inputPorts, outputPorts, config) {

    final override def portInstructions: Map[Port, Instruction] =
      compPortInstructions ++ devices.flatMap(_.portInstructions)

    final override def links: Map[Port, Port] =
      newLinks ++ devices.flatMap(_.links)

    // Composites should be composed of some other virtual devices.  We use this
    // to ensure that the links and the port instructions are correctly
    // accumulated.
    protected def devices: List[VirtualDevice[_]]

    // Each composite VD should define the links it adds.
    protected def newLinks: Map[Port, Port]

    // It is generally the case that composite VDs don't have port instructions
    // themselves, but they link together VDs which do.
    //
    // However, if there is any composite VD which needs to add some port
    // instructions, this method can still be overridden, this is just the
    // default.
    protected def compPortInstructions: Map[Port, Instruction] = Map.empty
  }

  abstract class VirtualDeviceBuilder[T <: VirtualDevice[_]](name: String) {
    def build: T
  }
}
