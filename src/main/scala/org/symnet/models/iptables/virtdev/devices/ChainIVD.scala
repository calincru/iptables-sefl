// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet
package models.iptables.virtdev
package devices

import models.iptables.core.{Chain, IPTIndex}

trait ChainIVDConfig {
  val tagDispatcher:  TagReturnDispatcher
  val contiguousIVDs: List[ContiguousIVD]
}

class ChainIVD(
    name:   String,
    config: ChainIVDConfig)
  extends CompositeVirtualDevice[ChainIVDConfig](
    name,
        // 1 input port
    1,
        // n + 2 output ports:
        //  * 0 - ACCEPT output port
        //  * 1 - DROP output port
        //  * [2; n + 2) - jumps to user-defined chains
    config.contiguousIVDs.length + 2,
    config) {

  override def devices: List[VirtualDevice[_]] =
    config.contiguousIVDs :+ config.tagDispatcher

  // TODO
  override def newLinks: Map[Port, Port] = Map.empty
}

class ChainIVDBuilder(
    name:  String,
    chain: Chain,
    index: IPTIndex) extends VirtualDeviceBuilder[ChainIVD](name) { self =>

  // TODO
  def build: ChainIVD = null
}
