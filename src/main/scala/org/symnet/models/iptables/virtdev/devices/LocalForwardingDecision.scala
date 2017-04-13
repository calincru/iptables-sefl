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
 *  It extends 'ForwardingDecision' as it is a particular one, with a routing
 *  table constructed out of the local ip addresses (see the builder).
 */
class LocalForwardingDecision(
    name:         String,
    routingTable: List[String])
  extends ForwardingDecision(
    name,
    2, // output ports:
       //   * to local process
       //   * to the forwarding decision (routing table)
    routingTable) {

  def localOutputPort:    Port = outputPort(0)
  def forwardOutputPort:  Port = outputPort(1)
}

class LocalForwardingDecisionBuilder(
    name:     String,
    localIps: List[Ipv4])
  extends VirtualDeviceBuilder[LocalForwardingDecision](name) {

  override def build: LocalForwardingDecision =
    new LocalForwardingDecision(name, makeRoutingTable(localIps))

  // Construct a routing table based on the local ips of a router; if one of
  // them is matched, the packet is forwarded to port 0 (that is the local
  // output port); otherwise, it is forward to port 1.
  private def makeRoutingTable(localIps: List[Ipv4]): List[String] =
    // 'routes' to the local process
    localIps.map(ip => ip.toString() + "/32 0") :+
    // 'route' to the forwarding process
    "0.0.0.0/0 1"
}
