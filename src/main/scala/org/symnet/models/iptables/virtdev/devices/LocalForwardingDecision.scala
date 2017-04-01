// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet
package models.iptables.virtdev
package devices

import types.net.Ipv4

/** This device represents the forwarding decision made by routers to know if a
 *  packet's destination is one of its interfaces.
 *
 *  The config represents the list of router interfaces' IPs.
 */
case class LocalForwardingDecision(
    name:     String,
    config:   List[Ipv4])
  extends RegularVirtualDevice[List[Ipv4]](
    name,
    1, // input port
    2, // output ports:
       //   * to local process
       //   * to the forwarding decision (routing table)
    config) {

  def inputPort:          Port = inputPort(0)
  def localOutputPort:    Port = outputPort(0)
  def forwardOutputPort:  Port = outputPort(1)

  // TODO
  override def portInstructions: Map[Port, Instruction] = Map.empty
}
