// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet
package models.iptables.virtdev
package devices

import types.net.Ipv4

trait RouterConfig {
  val localRD:      LocalForwardingDecision
  val fwdRD:        ForwardingDecision
  val localProcess: LocalProcess
}

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

  override def devices: List[VirtualDevice[_]] =
    List(config.localRD, config.fwdRD, config.localProcess)

  override def newLinks: Map[Port, Port] = {
    val local        = config.localRD
    val fwd          = config.fwdRD
    val localProcess = config.localProcess

    List(
      // Add links to the local forwarding decision.
      (0 until inputPorts).map(i => inputPort(i) -> local.inputPort).toMap,

      // Add link from local decision to local process.
      Map(local.localOutputPort -> localProcess.inputPort),

      // Add link from local decision to routing decision.
      Map(local.forwardOutputPort -> fwd.inputPort),

      // Add links from routing decision to output ports.
      (0 until outputPorts).map(i => fwd.outputPort(i) -> outputPort(i)).toMap
    ).flatten.toMap
  }
}

class RouterBuilder(
    name:         String,
    inputPorts:   Int,
    outputPorts:  Int,
    localIps:     List[Ipv4],
    routingTable: List[String]) extends VirtualDeviceBuilder[Router](name) {

  override def build: Router =
    new Router(name, inputPorts, outputPorts, new RouterConfig {
      val (localRD, fwdRD, localProcess) =
        (localRDDevice, fwdRDDevice, localProcessDevice)
    })

  protected val localRDDevice =
    new LocalForwardingDecisionBuilder(localName(name), localIps).build
  protected val fwdRDDevice =
    new ForwardingDecision(fwdName(name), outputPorts, routingTable)
  protected val localProcessDevice =
    new LocalProcess(procName(name))

  private def localName(routerName: String) = s"$routerName-localRD"
  private def fwdName  (routerName: String) = s"$routerName-fwdRD"
  private def procName (routerName: String) = s"$routerName-localProc"
}
