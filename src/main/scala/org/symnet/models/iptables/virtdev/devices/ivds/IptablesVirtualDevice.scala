// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet
package models.iptables.virtdev
package devices
package ivds

abstract class IptablesVirtualDevice[+Config](
    name: String,
    extraInputPorts: Int,
    extraOutputPorts: Int,
    config: Config)
  extends CompositeVirtualDevice[Config](
    name,
    1 + extraInputPorts,
    2 + extraOutputPorts,
    config) {

  protected def ivdPortInstructions: Map[Port, Instruction] = Map.empty

  // NOTE: Since some of the IVDs are actually regular VDs, we default these to
  // empty list/map.
  protected override def devices: List[VirtualDevice[_]] = Nil
  protected override def newLinks: Map[Port, Port] = Map.empty

  // We also "rename" the `compPortInstructions' method; subclasses should
  // instead use `ivdPortInstructions'.
  protected final override def compPortInstructions: Map[Port, Instruction] =
    ivdPortInstructions

  override def inputPort(which: Int): Port = super.inputPort(1 + which)
  override def outputPort(which: Int): Port = super.outputPort(2 + which)

  def inputPort: Port = super.inputPort(0)
  def acceptPort: Port = super.outputPort(0)
  def dropPort: Port = super.outputPort(1)
}
