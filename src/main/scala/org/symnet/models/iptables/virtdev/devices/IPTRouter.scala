// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet
package models.iptables.virtdev
package devices

import ivds._
import models.iptables.core.{Chain, IPTIndex, Table}
import types.net.Ipv4

/** An iptables enhanced router is built as follows:
 -
 *     +---------------------------------------------------+
 *     |                       LLL                         |
 *  --o|->111-----+             ^                   +----->|o--
 *     |          |       +--->444<----+            |      |
 *     |          v       |            |            |      |
 *  --o|->111--->222-->333+-->555-->666+-->777-->888+----->|o--
 *   . |          ^                                 .  .   | .
 *   . |          |                                 .  .   | .
 *  --o|->111-----+                                 +----->|o--
 *     |                                                   |
 *     +------------------------------------------ --------+
 *
 *
 *  --o -- these are input/output ports
 *  111 -- these are the VDs that set the input interface as a metadata in the
 *         packet.
 *  222 -- this is the PREROUTING chain.
 *  333 -- this is the first routing decision; it either sends the packets to a
 *         local process or determines the output interface of the packet and
 *         stores it as a metadata.
 *  444 -- this is the LOCAL chain.
 *  LLL -- this is the local process; it usually acts as a sink (simply drops
 *         the packets)
 *  555 -- this is the FORWARDING chain.
 *  666 -- this is the second (and final) routing decision; it works the same as
 *         the previous one.
 *  777 -- this is the POSTROUTING chain.
 *  888 -- this is where the actual dispatching is done (fork - forward) based
 *         on the output port metadata set by the routing decision.
 */

trait IPTRouterConfig {
  // Usual router logic.
  val localProcess: LocalProcess
  val preFwdRD:     RoutingDecision
  val postFwdRD:    RoutingDecision

  // iptables specific.
  val inPortSetters:  List[InputPortSetter]
  val preroutingIVD:  SeqChainIVD
  val forwardingIVD:  SeqChainIVD
  val localIVD:       SeqChainIVD
  val postroutingIVD: SeqChainIVD
  val outDispatcher:  OutputPortDispatcher
}

class IPTRouter(
    name:         String,
    inputPorts:   Int,
    outputPorts:  Int,
    config:       IPTRouterConfig)
  extends CompositeVirtualDevice[IPTRouterConfig](
    name,
    inputPorts,
    outputPorts,
    config) {

  override def devices: List[VirtualDevice[_]] =
    List(
      // Usual router implementation components.
      config.localProcess,
      config.preFwdRD,
      config.postFwdRD,

      // iptables specific.
      config.preroutingIVD,
      config.forwardingIVD,
      config.localIVD,
      config.postroutingIVD,
      config.outDispatcher) ++ config.inPortSetters

  override def newLinks: Map[Port, Port] = {
    List(
      // Add links from router's input ports to the input port setters.
      (0 until inputPorts).map(i =>
          inputPort(i) -> config.inPortSetters(i).inputPort),

      // Add links from the port setters to the prerouting IVD.
      (0 until inputPorts).map(i =>
          config.inPortSetters(i).outputPort -> config.preroutingIVD.inputPort),

      Map(
        // Add link from the prerouting IVD to the first routing decision.
        config.preroutingIVD.outputPort -> config.preFwdRD.inputPort,

        // Link the first routing decision as expected.
        config.preFwdRD.localOutputPort -> config.localIVD.inputPort,
        config.preFwdRD.fwdOutputPort   -> config.forwardingIVD.inputPort,

        // Link the LOCAL chain to the local process
        config.localIVD.inputPort -> config.localProcess.inputPort,

        // Link the FORWARDING chain to the next routing decision.
        config.forwardingIVD.outputPort -> config.postFwdRD.inputPort,

        // Link the second routing decision as expected.
        config.postFwdRD.localOutputPort -> config.localIVD.inputPort,
        config.postFwdRD.fwdOutputPort   -> config.postroutingIVD.inputPort,

        // Link the POSTROUTING chain to the output dispatcher.
        config.postroutingIVD.outputPort -> config.outDispatcher.inputPort),

      // Link the output dispatcher to router's output interfaces.
      (0 until outputPorts).map(
        i => config.outDispatcher.outputPort(i) -> outputPort(i))
    ).flatten.toMap
  }
}

class IPTRouterBuilder(
    name:         String,
    inputPorts:   Int,
    outputPorts:  Int,
    localIps:     List[Ipv4],
    routingTable: RoutingTable,
    iptables:     List[Table])
  extends VirtualDeviceBuilder[IPTRouter](name) { self =>

  override def build: IPTRouter =
    new IPTRouter(name, inputPorts, outputPorts, new IPTRouterConfig {
      val localProcess = makeLocalProcess
      val preFwdRD     = makeRoutingDecision("prefwd")
      val postFwdRD    = makeRoutingDecision("postfwd")

      val inPortSetters  = makeInSetters
      val preroutingIVD  = makeChainsIVD(Nil)
      val forwardingIVD  = makeChainsIVD(Nil)
      val localIVD       = makeChainsIVD(Nil)
      val postroutingIVD = makeChainsIVD(Nil)
      val outDispatcher  = makeOutDispatcher
    })

  protected lazy val index = new IPTIndex(iptables)

  protected def makeLocalProcess = LocalProcess(s"$name-local-proc")

  protected def makeRoutingDecision(id: String) =
    RoutingDecision(s"$name-rd-$id", new RoutingDecisionConfig {
      val localIps = self.localIps
      val routingTable = self.routingTable
    })

  // TODO: Implement these.
  protected def makeInSetters: List[InputPortSetter] = Nil
  protected def makeChainsIVD(chains: List[Chain]): SeqChainIVD = null
  protected def makeOutDispatcher: OutputPortDispatcher = null
}
