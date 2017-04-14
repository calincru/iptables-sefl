// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet
package models.iptables.virtdev
package devices

import org.change.v2.analysis.processingmodels.instructions.{Fail, Fork}

import models.iptables.core.Rule

case class ContiguousIVD(
    name:  String,
    rules: List[Rule])
  extends RegularVirtualDevice[List[Rule]](
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
    rules) {

  def inputPort:   Port = inputPort(0)
  def acceptPort:  Port = outputPort(0)
  def dropPort:    Port = outputPort(1)
  def returnPort:  Port = outputPort(2)
  def jumpPort:    Port = outputPort(3)
  def nextIVDport: Port = outputPort(4)

  override def portInstructions: Map[Port, Instruction] = List(
    // Generate input port instructions.
    // Map(inputPort -> Fork(rules.map(_.seflCode): _*)),

    // Fail if the drop port is reached.
    Map(dropPort -> Fail(s"Packet dropped by $name"))
  ).flatten.toMap
}
