// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet
package models.iptables.virtdev
package devices

import org.change.v2.analysis.processingmodels.instructions.Fail

import models.iptables.core.Rule

trait ContiguousIVDConfig {
  val rules: List[Rule]
  val index: Int
}

case class ContiguousIVD(
    name:   String,
    config: ContiguousIVDConfig)
  extends RegularVirtualDevice[ContiguousIVDConfig](
    name,
      // single input port
    1,
      // 5 output ports:
      //  * 0 - ACCEPT output port
      //  * 1 - DROP output port
      //  * 2 - RETURN output port
      //  * 3 - towards its corresponding user-defined chain
      //  * 4 - next contiguous IVD
    5,
    config) {

  def inputPort:   Port = inputPort(0)
  def acceptPort:  Port = outputPort(0)
  def dropPort:    Port = outputPort(1)
  def returnPort:  Port = outputPort(2)
  def jumpPort:    Port = outputPort(3)
  def nextIVDport: Port = outputPort(4)

  override def portInstructions: Map[Port, Instruction] = List(
    // TODO: Add port instructions

    Map(dropPort -> Fail(s"Packet dropped by $name"))
  ).flatten.toMap
}
