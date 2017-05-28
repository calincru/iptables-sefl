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

  protected override def ivdPortInstructions: Map[Port, Instruction] = {
    val ctstateTagName = ctstateTag(deviceId)

    Map(inputPort ->
      // Here goes the logic for state transitions. So far we only handle the
      // transition from NEW to ESTABLISHED.
      //
      // FIXME: Consider using multiple output ports which are all linked to the
      // accept port; this would allow an `egress' style selection.
      If(Constrain(ctstateTagName, :==:(ConstantValue(ConnectionState.New.id))),
         Assign(ctstateTagName, ConstantValue(ConnectionState.Established.id)),
         NoOp)
    )
  }
}
