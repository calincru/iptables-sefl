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
}
