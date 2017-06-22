// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet
package models.iptables
package virtdev
package devices.ivds

// 3rd-party
// -> Symnet
import org.change.v2.analysis.expression.concrete.ConstantValue
import org.change.v2.analysis.processingmodels.instructions._

// project
import extensions.conntrack.ConnectionState

case class ConnectionTrackingIVD(name: String, deviceId: String)
  extends IptablesVirtualDevice[String](name, 0, 0, deviceId) {

  // NOTE: Drop port currently unused here.

  protected override def ivdPortInstructions: Map[Port, Instruction] = {
    val ctstateTagName = ctstateTag(deviceId)
    val ctstateTransitions = Map(
      ConnectionState.Unset -> ConnectionState.New,
      ConnectionState.New -> ConnectionState.Established
    )

    Map(inputPort -> Fork((ctstateTransitions map {
      case (from, to) => InstructionBlock(
        Constrain(ctstateTagName, :==:(ConstantValue(from.id))),
        Assign(ctstateTagName, ConstantValue(to.id)),
        Forward(acceptPort)
      )
    }).toSeq: _*))
  }
}
