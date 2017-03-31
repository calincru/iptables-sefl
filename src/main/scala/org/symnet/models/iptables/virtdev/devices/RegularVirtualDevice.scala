// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet
package models.iptables
package virtdev
package devices

abstract class RegularVirtualDevice[+Config](
    name:         String,
    inputPorts:   Int,
    outputPorts:  Int,
    config:       Config)
  extends VirtualDevice[Config](name, inputPorts, outputPorts, config) {

  def portInstructions: Map[Port, Instruction]
}
