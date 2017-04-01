// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet
package models.iptables.virtdev
package devices

import models.iptables.core.Rule

case class ContiguousIVD(
    name: String,
    rules: List[Rule])
  extends RegularVirtualDevice[Unit](
    name,
      // single input port
    1,
      // 4 output ports:
      //  * 0 - ACCEPT output port
      //  * 1 - DROP output port
      //  * 2 - next contiguous IVD
      //  * 3 - towards its corresponding user-defined chain
    4,
    ()) {

  def inputPort:   Port = inputPort(0)
  def acceptPort:  Port = outputPort(0)
  def dropPort:    Port = outputPort(1)
  def nextIVDport: Port = outputPort(2)
  def jumpPort:    Port = outputPort(3)

  // TODO
  override def portInstructions: Map[Port, Instruction] = Map.empty
}
