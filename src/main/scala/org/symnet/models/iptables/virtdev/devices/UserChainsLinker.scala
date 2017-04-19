// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet
package models.iptables.virtdev
package devices

trait UserChainsLinkerConfig {
  // TODO: Add fields
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

  // TODO: Add user-defined chains.
  // This Virtual Device only owns the user defined chains.
  override def devices: List[VirtualDevice[_]] = Nil

  // TODO: Add links
  override def newLinks: Map[Port, Port] = Map.empty
}
