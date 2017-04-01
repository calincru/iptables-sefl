// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet
package models.iptables.virtdev
package devices

import org.change.v2.analysis.processingmodels.instructions.{:==:, Fork, Forward, Constrain}
import org.change.v2.analysis.expression.concrete.ConstantValue

case class TagReturnDispatcher(
    name: String,
    outputPorts: Int,
    tag: String)
  extends RegularVirtualDevice[String](
    name,
    1, // one input port
    outputPorts,
    tag) {

  def inputPort: Port = inputPort(0)

  override def portInstructions: Map[Port, Instruction] =
    // Fork to all output ports
    Map(inputPort ->
          Fork((0 until outputPorts).map(i => Forward(outputPort(i))): _*)) ++
    // Constrain the tag value so that it gets passed only through the expected
    // one.
    (0 until outputPorts).map(
      i => outputPort(i) -> Constrain(tag, :==:(ConstantValue(i)))).toMap
}
