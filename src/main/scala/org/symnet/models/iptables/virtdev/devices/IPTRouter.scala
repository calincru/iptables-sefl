// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet
package models.iptables.virtdev
package devices

import types.net.Ipv4

import models.iptables.core.{IPTIndex, Table}

trait IPTRouterConfig extends RouterConfig {
  val preroutingIVDs:  List[ChainIVD]
  val postroutingIVDs: List[ChainIVD]
  val forwardingIVD:   ChainIVD
  val localIVD:        ChainIVD
}

class IPTRouter(
    name:         String,
    inputPorts:   Int,
    outputPorts:  Int,
    config:       IPTRouterConfig)
  extends Router(name, inputPorts, outputPorts, config) {

  override def devices: List[VirtualDevice[_]] =
    super.devices ++
    config.preroutingIVDs ++
    config.postroutingIVDs ++
    List(config.forwardingIVD, config.localIVD)

  // TODO
  // NOTE: We override router's links.
  override def newLinks: Map[Port, Port] = Map.empty
}

class IPTRouterBuilder(
    name:         String,
    inputPorts:   Int,
    outputPorts:  Int,
    localIps:     List[Ipv4],
    routingTable: List[String],
    iptables:     List[Table])
  extends RouterBuilder(name, inputPorts, outputPorts, localIps, routingTable) {

  override def build: IPTRouter =
    new IPTRouter(name, inputPorts, outputPorts, new IPTRouterConfig {
      val (localRD, fwdRD, localProcess) =
        (localRDDevice, fwdRDDevice, localProcessDevice)
      val (preroutingIVDs, postroutingIVDs, forwardingIVD, localIVD) = makeIVDs
    })

  protected lazy val index = new IPTIndex(iptables)

  protected def makeIVDs = {
    // TODO: Use the index to prepare the IVDs

    (Nil, Nil, null, null)
  }
}
