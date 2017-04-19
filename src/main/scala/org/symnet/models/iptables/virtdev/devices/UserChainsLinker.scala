// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet
package models.iptables.virtdev
package devices

import ivds.ChainIVD

trait UserChainsLinkerConfig {
  // List of user defined chain IVDs indices.
  val userChainIVDIndices: List[Int]

  // Data structures used to set the `hidden' links between Chain IVDs.
  val chainInNeighsMap:  Map[Int, List[Int]]
  val chainOutNeighsMap: Map[Int, List[Int]]
  val chainIVDsMap:      Map[Int, ChainIVD]
}

case class UserChainsLinker(
    name:   String,
    config: UserChainsLinkerConfig)
  extends CompositeVirtualDevice[UserChainsLinkerConfig](
    name,
      // no input/output ports
    0,
    0,
    config) {

  // This Virtual Device only owns the user defined chains.
  override def devices: List[VirtualDevice[_]] =
    config.userChainIVDIndices.map(config.chainIVDsMap(_))

  // TODO: Add links
  override def newLinks: Map[Port, Port] = Map.empty
}
