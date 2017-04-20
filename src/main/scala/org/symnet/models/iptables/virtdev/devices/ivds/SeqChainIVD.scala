// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet
package models.iptables.virtdev
package devices
package ivds

trait SeqChainIVDConfig {
  val chains: List[ChainIVD]
}

class SeqChainIVD(
    name:   String,
    config: SeqChainIVDConfig)
  extends CompositeVirtualDevice[SeqChainIVDConfig](
    name,
      // input port
    1,
      // output port
    1,
    config) {

  def inputPort:  Port = inputPort(0)
  def outputPort: Port = outputPort(0)

  override def devices: List[VirtualDevice[_]] = config.chains

  override def newLinks: Map[Port, Port] = {
    val chains = config.chains

    List(
      // Add link from its input port to the init port of the first chain IVD.
      Map(inputPort -> chains(0).initPort),

      // Add links from the accept port of a chain IVD to the next, except for
      // the last one.
      (0 until chains.length - 1).map(
        i => chains(i).acceptPort -> chains(i + 1).initPort),

      // Add a link from the accept port of the last one to the output port of
      // this IVD.
      Map(chains.last.acceptPort -> outputPort)
    ).flatten.toMap
  }
}

class SeqChainIVDBuilder(
    name: String,
    chains: List[ChainIVD])
  extends VirtualDeviceBuilder[SeqChainIVD](name) { self =>

  override def build: SeqChainIVD = new SeqChainIVD(name, new SeqChainIVDConfig {
    val chains = self.chains
  })
}
