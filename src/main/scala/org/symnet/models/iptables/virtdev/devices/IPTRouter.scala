// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet
package models.iptables.virtdev
package devices

import ivds._
import models.iptables.core.{Chain, Table}
import types.net.Ipv4

/** An iptables enhanced router is built as follows:
 -
 *     +---------------------------------------------------+
 *     |                       LLL                         |
 *  --o|->111-----+             ^                   +----->|o--
 *     |          |       +--->444<----+            |      |
 *     |          v       |            |            |      |
 *  --o|->111--->222-->333*-->555-->666*-->777-->888*----->|o--
 *   . |          ^                                 .  .   | .
 *   . |          |                                 .  .   | .
 *  --o|->111-----+                                 +----->|o--
 *     |                                                   |
 *     +---------------------------------------------------+
 *
 *
 *  --o -- these are input/output ports
 *  111 -- these are the VDs that set the input interface as a metadata in the
 *         packet.
 *  222 -- this is the PREROUTING chain.
 *  333 -- this is the first routing decision; it either sends the packets to a
 *         local process or determines the output interface of the packet and
 *         stores it as a metadata.
 *  444 -- this is the INPUT chain.
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
  val preroutingIVD:  IVDSequencer
  val forwardingIVD:  IVDSequencer
  val inputIVD:       IVDSequencer
  val postroutingIVD: IVDSequencer
  val outDispatcher:  OutputPortDispatcher

  // The UserChainsLinker is a virtual device that links together ChainIVDs
  // (jump/return ports).
  //
  // NOTE: It doesn't have any input or output ports, it just defines links
  // between existing ChainIVDs.
  val chainsLinker: UserChainsLinker
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

  protected override def devices: List[VirtualDevice[_]] =
    List(
      config.inPortSetters,

      List(
        // Usual router implementation components.
        config.localProcess,
        config.preFwdRD,
        config.postFwdRD,

        // iptables specific.
        config.preroutingIVD,
        config.forwardingIVD,
        config.inputIVD,
        config.postroutingIVD,
        config.outDispatcher,

        // The chains linker.
        config.chainsLinker)
    ).flatten

  protected override def newLinks: Map[Port, Port] = {
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
        config.preFwdRD.localOutputPort -> config.inputIVD.inputPort,
        config.preFwdRD.fwdOutputPort   -> config.forwardingIVD.inputPort,

        // Link the INPUT chain to the local process
        config.inputIVD.inputPort -> config.localProcess.inputPort,

        // Link the FORWARDING chain to the next routing decision.
        config.forwardingIVD.outputPort -> config.postFwdRD.inputPort,

        // Link the second routing decision as expected.
        config.postFwdRD.localOutputPort -> config.inputIVD.inputPort,
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
    inputIpsMap:  Map[String, Ipv4],
    outputIpsMap: Map[String, Ipv4],
    routingTable: RoutingTable,
    iptables:     List[Table])
  extends VirtualDeviceBuilder[IPTRouter](name) { self =>

  // NOTE: The input ports and the output ports should have different names for
  // now.
  require((inputIpsMap.keySet & outputIpsMap.keySet).isEmpty)

  override def build: IPTRouter =
    new IPTRouter(name, inputPorts, outputPorts, new IPTRouterConfig {
      val localProcess = makeLocalProcess
      val preFwdRD     = makeRoutingDecision("prefwd")
      val postFwdRD    = makeRoutingDecision("postfwd")

      val inPortSetters  = makeInSetters
      val preroutingIVD  = makeSeqChains("PREROUTING")
      val forwardingIVD  = makeSeqChains("FORWARDING")
      val inputIVD       = makeSeqChains("INPUT")
      val postroutingIVD = makeSeqChains("POSTROUTING")
      val outDispatcher  = makeOutDispatcher

      val chainsLinker = makeChainsLinker
    })

  ///
  /// Helper methods.
  ///

  protected def makeLocalProcess = LocalProcess(s"$name-local-proc")

  protected def makeRoutingDecision(id: String) =
    RoutingDecision(s"$name-rd-$id", new RoutingDecisionConfig {
      val localIpsMap = self.inputIpsMap ++ self.outputIpsMap
      val routingTable = self.routingTable
      val portsMap = self.portsMap
    })

  protected def makeInSetters: List[InputPortSetter] =
    (0 until inputPorts).map(InputPortSetter(s"$name-port-setter", _)).toList

  protected def makeSeqChains(chainName: String): IVDSequencer = {
    val chains = index.chainsByName(chainName)

    new IVDSequencerBuilder(
      s"$name-seq-$chainName",
      chains.map(c => chainIVDsMap(chainIndices(c)))
    ).build
  }

  protected def makeOutDispatcher: OutputPortDispatcher =
    OutputPortDispatcher(s"$name-output-dispatcher", outputPorts)

  protected def makeChainsLinker: UserChainsLinker =
    UserChainsLinker(s"$name-chains-linker", new UserChainsLinkerConfig {
      val userChainIVDIndices = index.userChains.map(c => chainIndices(c))

      val chainInNeighsMap  = self.chainInNeighsMap
      val chainOutNeighsMap = self.chainOutNeighsMap
      val chainIVDsMap      = self.chainIVDsMap
    })

  ///
  /// Helper data structures.
  ///

  protected val index: IPTIndex = new IPTIndex(iptables)

  protected val chainIndices: Map[Chain, Int] =
    index.allChains.zipWithIndex.toMap

  protected val chainInNeighsMap: Map[Int, List[Int]] =
    chainIndices map {
      case (chain, idx) =>
        idx -> index.inAdjacencyLists(chain).map(c => chainIndices(c)).toList
    }

  protected val chainOutNeighsMap: Map[Int, List[Int]] =
    chainIndices map {
      case (chain, idx) =>
        idx -> index.outAdjacencyLists(chain).map(c => chainIndices(c)).toList
    }

  protected val chainIVDsMap: Map[Int, ChainIVD] =
    chainIndices map {
      case (chain, idx) => idx ->
        new ChainIVDBuilder(
          s"$name-chainIVD-${chain.name}",
          chain,
          index.chainsToTables(chain),
          idx,
          index.chainsSplitSubrules(chain),
          chainInNeighsMap(idx),
          portsMap
        ).build
    }

  private val inputPortNames = inputIpsMap.keys.toList
  private val outputPortNames = outputIpsMap.keys.toList

  private val inputPorts  = inputPortNames.length
  private val outputPorts = outputPortNames.length

  private val portsMap = inputPortNames.zipWithIndex.toMap ++
                         outputPortNames.zipWithIndex.toMap
}
