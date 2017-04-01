// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet
package models.iptables.virtdev
package devices

import types.net.Ipv4

case class RouterConfig(
    localRD:      LocalForwardingDecision,
    fwdRD:        ForwardingDecision,
    localProcess: LocalProcess)

class Router(
    name:         String,
    inputPorts:   Int,
    outputPorts:  Int,
    config:       RouterConfig)
  extends CompositeVirtualDevice[RouterConfig](
    name,
    inputPorts,
    outputPorts,
    config) {

  def localRD:      LocalForwardingDecision = config.localRD
  def fwdRD:        ForwardingDecision      = config.fwdRD
  def localProcess: LocalProcess            = config.localProcess
}

case class RouterBuilder(
    name:         String,
    inputPorts:   Int,
    outputPorts:  Int,
    localIps:     List[Ipv4],    // IPs of local interfaces
    routingTable: List[String])  // routing table
  extends VirtualDeviceBuilder[Router](name) {

  override def build: Router =
    new Router(name, inputPorts, outputPorts, RouterConfig(
        LocalForwardingDecisionBuilder(localRDName, localIps).build,
        ForwardingDecisionBuilder(fwdRDName, outputPorts, routingTable).build,
        LocalProcessBuilder(localProcessName).build))

  private val localRDName      = s"$name-localRD"
  private val fwdRDName        = s"$name-fwdRD"
  private val localProcessName = s"$name-localProc"
}
