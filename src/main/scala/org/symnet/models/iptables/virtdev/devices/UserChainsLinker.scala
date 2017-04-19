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
      // no input ports
    0,
      // no output ports
    0,
    config) {

  // This Virtual Device only owns the user defined chains.
  override def devices: List[VirtualDevice[_]] =
    config.userChainIVDIndices.map(i => config.chainIVDsMap(i))

  // NOTE: There is no need to check whether a jumped-to chain is a user-defined
  // one as that is ensured as part of the validation.
  //
  // See classes `ChainIVD', `InputTagDispatcher' and `OutputTagDispatcher' from
  // the `ivds/' subdir.
  override def newLinks: Map[Port, Port] =
    List(
      // Add jump ports.
      config.chainIVDsMap.map {
        case (idx, ivd) => config.chainOutNeighsMap(idx).zipWithIndex.map {
          case (neighIdx, portId) =>
            ivd.jumpPort(portId) -> config.chainIVDsMap(neighIdx).initPort
        }.toMap
      }.flatten.toMap,

      // Add backlink (RETURN) ports.
      config.chainIVDsMap.map {
        case (idx, ivd) => config.chainInNeighsMap(idx).zipWithIndex.map {
          case (neighIdx, portId) =>
            ivd.backlinkPort(portId) -> config.chainIVDsMap(neighIdx).inputPort
        }.toMap
      }.flatten.toMap
    ).flatten.toMap
}
