// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet
package models.iptables.virtdev

import devices.VirtualDevice

/** A 'NetworkModel' aggregates multiple devices alongside the links between
 *  them.
 *
 *  It can be passed to an executor to trace the flows through the modeled
 *  network.
 */
case class NetworkModel(
    instructions: Map[Port, Instruction],
    links:        Map[Port, Port]) {

  def ++(other: NetworkModel): NetworkModel =
    NetworkModel(instructions ++ other.instructions,
                 links ++ other.links)
}

object NetworkModel {

  def apply[T <: VirtualDevice[_]](t: T): NetworkModel =
    NetworkModel(t.portInstructions, t.links)
}
