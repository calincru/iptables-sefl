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
  extends CompositeVirtualDevice[UserChainsLinkerConfig](name, 0, 0, config) {

  // This Virtual Device only owns the user defined chains.
  protected override def devices: List[VirtualDevice[_]] =
    config.userChainIVDIndices.map(i => config.chainIVDsMap(i))

  // See also classes `ChainIVD', `InputTagDispatcher' and `OutputTagDispatcher'
  // from the `ivds/' subdir.
  protected override def newLinks: Map[Port, Port] =
    List(
      // Add jump ports.
      config.chainIVDsMap.map {
        case (idx, ivd) => config.chainOutNeighsMap(idx).zipWithIndex.map {
          case (neighIdx, portId) =>
            // NOTE: We link it to the `init' port.
            ivd.jumpPort(portId) -> config.chainIVDsMap(neighIdx).initPort
        }.toMap
      }.flatten.toMap,

      // Add backlink (RETURN) ports.
      config.chainIVDsMap.map {
        case (idx, ivd) => config.chainInNeighsMap(idx).zipWithIndex.map {
          case (neighIdx, portId) =>
            // NOTE: We link it to the `input' port.
            ivd.backlinkPort(portId) -> config.chainIVDsMap(neighIdx).inputPort
        }.toMap
      }.flatten.toMap
    ).flatten.toMap
}
