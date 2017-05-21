// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet
package models.iptables

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
  val NfmarkTag = "nfmark"
  val CtmarkTag = "ctmark"
}
