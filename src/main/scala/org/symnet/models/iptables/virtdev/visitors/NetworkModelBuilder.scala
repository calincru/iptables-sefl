// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet
package models.iptables.virtdev
package visitors

import scala.collection.mutable.{Map => IMap} // :(

import devices._

class NetworkModelBuilder extends VirtualDeviceVisitor {

  def build: NetworkModel = NetworkModel(instructions.toMap, links.toMap)

  // For regular device we just add them to the network model.
  def visit(rvd: RegularVirtualDevice[_]): Unit = addDevice(rvd)

  def visit(router: Router): Unit = {
    val local        = router.localRD
    val fwd          = router.fwdRD
    val localProcess = router.localProcess

    // Add its 2 aggregated 'devices'.
    visit(local)
    visit(fwd)
    visit(localProcess)

    // Add links to the local forwarding decision.
    for (i <- 0 until router.inputPorts)
      addLink(router.inputPort(i), local.inputPort)

    // Add link from local to fwd.
    addLink(local.forwardOutputPort, fwd.inputPort)

    // Add link from local decision to local process.
    addLink(local.localOutputPort, localProcess.inputPort)

    // Add links from routing decision to router's output ports.
    for (i <- 0 until router.outputPorts)
      addLink(fwd.outputPort(i), router.outputPort(i))
  }


  private def addDevice(device: VirtualDevice[_]) =
    instructions ++= device.portInstructions
  private def addLink(fromPort: Port, toPort: Port) =
    links += (fromPort -> toPort)

  private val instructions: IMap[Port, Instruction] = IMap.empty
  private val links:        IMap[Port, Port]        = IMap.empty
}
