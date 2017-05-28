// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet
package models.iptables.virtdev
package devices
package ivds

trait IVDSequencerConfig {
  val ivds: List[IptablesVirtualDevice[_]]
}

class IVDSequencer(
    name:   String,
    config: IVDSequencerConfig)
  extends IptablesVirtualDevice[IVDSequencerConfig](name, 0, 0, config) {

  protected override def devices: List[VirtualDevice[_]] = config.ivds

  protected override def newLinks: Map[Port, Port] = {
    val ivds = config.ivds

    List(
      // Add link from its input port to the input port of the first ivd.
      Map(inputPort -> ivds(0).inputPort),

      // Add links from the accept port of a ivd to the next, except for the
      // last one.
      (0 until ivds.length - 1).map(
        i => ivds(i).acceptPort -> ivds(i + 1).inputPort),

      // Add a link from the accept port of the last one to the output port of
      // this ivd.
      Map(ivds.last.acceptPort -> acceptPort)
    ).flatten.toMap
  }
}

class IVDSequencerBuilder(
    name: String,
    ivds: List[IptablesVirtualDevice[_]])
  extends VirtualDeviceBuilder[IVDSequencer](name) { self =>

  override def build: IVDSequencer =
    new IVDSequencer(name, new IVDSequencerConfig {
      val ivds = self.ivds
    })
}
