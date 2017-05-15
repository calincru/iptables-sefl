// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet
package models.iptables.virtdev
package devices

import ivds.ChainIVD

trait IVDSequencerConfig {
  val chainIVDs: List[ChainIVD]
}

class IVDSequencer(
    name:   String,
    config: IVDSequencerConfig)
  extends CompositeVirtualDevice[IVDSequencerConfig](
    name,
      // input port
    1,
      // output port
    1,
    config) {

  def inputPort:  Port = inputPort(0)
  def outputPort: Port = outputPort(0)

  protected override def devices: List[VirtualDevice[_]] = config.chainIVDs

  protected override def newLinks: Map[Port, Port] = {
    val chainIVDs = config.chainIVDs

    List(
      // Add link from its input port to the init port of the first chain IVD.
      Map(inputPort -> chainIVDs(0).initPort),

      // Add links from the accept port of a chain IVD to the next, except for
      // the last one.
      (0 until chainIVDs.length - 1).map(
        i => chainIVDs(i).acceptPort -> chainIVDs(i + 1).initPort),

      // Add a link from the accept port of the last one to the output port of
      // this IVD.
      Map(chainIVDs.last.acceptPort -> outputPort)
    ).flatten.toMap
  }
}

class IVDSequencerBuilder(
    name: String,
    chainIVDs: List[ChainIVD])
  extends VirtualDeviceBuilder[IVDSequencer](name) { self =>

  override def build: IVDSequencer =
    new IVDSequencer(name, new IVDSequencerConfig {
      val chainIVDs = self.chainIVDs
    })
}
