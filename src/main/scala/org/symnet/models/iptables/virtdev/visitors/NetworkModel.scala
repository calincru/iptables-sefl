// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet
package models.iptables.virtdev
package visitors

import devices.VirtualDevice

/** A 'NetworkModel' aggregates multiple devices alongside the links between
 *  them.
 *
 *  It can be passed to an executor to trace the flows through the modeled
 *  network.
 */
abstract class NetworkModel {

  def addDevice(device: VirtualDevice[_]): NetworkModel

  def addLink(
      fromDevice: VirtualDevice[_],
      fromPort:   Port,
      toDevice:   VirtualDevice[_],
      toPort:     Port)
}
