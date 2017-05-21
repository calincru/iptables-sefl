// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet
package models.iptables

// TODO: Probably most of the tag names here should be device specific, so we
// should probably rewrite them as functions of device ids.

package object virtdev {
  type Port = String
  type Instruction = org.change.v2.analysis.processingmodels.Instruction

  // A Routing Table is an ordered list of pairs (IP, Output Port), where the
  // IP is a network prefix (could be a host address to, if the mask is /32).
  type RoutingTable = List[(types.net.Ipv4, String)]

  val InputDispatchTag  = "input-dispatch"
  val OutputDispatchTag = "output-dispatch"

  val InputPortTag  = "input-port"
  val OutputPortTag = "output-port"

  // Holds the IP of the interface a packet has been received on / will be sent
  // through.
  val InputIpTag = "input-ip"
  val OutputIpTag = "output-ip"

  // Functions used to build unique tag names for NAT handling.
  def snatFromIp(id: String): String = s"$id-snat-from-ip"
  def snatFromPort(id: String): String = s"$id-snat-from-port"
  def snatToIp(id: String): String = s"$id-snat-to-ip"
  def snatToPort(id: String): String = s"$id-snat-to-port"

  def dnatFromIp(id: String): String = s"$id-dnat-from-ip"
  def dnatFromPort(id: String): String = s"$id-dnat-from-port"
  def dnatToIp(id: String): String = s"$id-dnat-to-ip"
  def dnatToPort(id: String): String = s"$id-dnat-to-port"

  // Metadata tag names for MARK/CONNMARK fields.
  //
  // NOTE: The difference between the two is that ctmark is 'remembered' as part
  // of flow's metadata, while nfmark is forgotten when the packet leaves the
  // device.
  val CtmarkTag = "ctmark"
  def nfmarkTag(id: String): String = s"$id-nfmark"

  // Metadata tag names for CONNTRACK fields.
  val CtstateTag = "ctstate"
  val SnatStateTag = "snat-state"
  val DnatStateTag = "dnat-state"
}
