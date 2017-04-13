// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet
package models.iptables.virtdev
package devices

import org.change.v2.analysis.processingmodels.instructions.Assign
import org.change.v2.analysis.expression.concrete.ConstantValue

import models.iptables.core.{BuiltinChain, Chain, IPTIndex, Policy, Rule, UserChain}
import Policy._

trait ChainIVDConfig {
  // IVDs
  val inDispatcher:   InputTagDispatcher
  val contiguousIVDs: List[ContiguousIVD]
  val outDispatcher:  OutputTagDispatcher

  // The default policy of the chain modelled by this IVD.
  val policy: Policy

  // The index of this chain, as it is referred back by other chains.
  val index: Int
}

class ChainIVD(
    name:   String,
    config: ChainIVDConfig)
  extends CompositeVirtualDevice[ChainIVDConfig](
    name,
        // 1 input port
    1,
        // (2 + n + m) output ports:
        //  * 0 - ACCEPT output port
        //  * 1 - DROP output port
        //  * [2; 2 + n) - jumps to user-defined chains
        //  * [2 + n; 2 + n + m) - backlinks
    2 + config.contiguousIVDs.length + config.outDispatcher.outputPorts,
    config) {

  def inputPort:Port = inputPort(0)
  def acceptPort: Port = outputPort(0)
  def dropPort: Port = outputPort(1)
  def jumpPort(n: Int): Port = outputPort(2 + n)
  def backlinkPort(n: Int): Port =
    outputPort(2 + config.contiguousIVDs.length + n)

  override def devices: List[VirtualDevice[_]] =
    config.contiguousIVDs ++
    List(config.inDispatcher, config.outDispatcher)

  override def newLinks: Map[Port, Port] = {
    val inDispatcher  = config.inDispatcher
    val ivds          = config.contiguousIVDs
    val outDispatcher = config.outDispatcher
    val policy        = config.policy
    val backlinks     = config.outDispatcher.outputPorts

    List(
      ///
      /// input -> tag dispatcher
      ///
      Map(inputPort -> inDispatcher.inputPort),

      ///
      /// tag dispatcher -> IVDs
      ///
      // Link tag dispatcher's outputs to IVDs.
      (0 until ivds.length).map(
        i => inDispatcher.outputPort(i) -> ivds(i).inputPort),

      ///
      /// Setup output ports for IVDs
      ///
      // Link IVDs' accept ports to this device's ACCEPT output port
      ivds.map(_.acceptPort -> acceptPort),

      // Link IVD' drop ports to this device's DROP output port
      //
      // NOTE: The only reason this is done is to forward all drops to the same
      // port, in case we want to add some common logic at some point.
      ivds.map(_.dropPort -> dropPort),

      // Link all IVDs to the port controlling RETURNs.
      ivds.map(_.returnPort -> outDispatcher.inputPort),

      // Link all IVDs to their corresponding jump ports.
      (0 until ivds.length).map(
        i => ivds(i).jumpPort -> jumpPort(i)),

      // Link all IVDs but the last one to the next one.
      (0 until ivds.length - 1).map(
        i => ivds(i).nextIVDport -> ivds(i + 1).inputPort),

      // Link the last one according to the policy.
      Map(ivds.last.nextIVDport -> (policy match {
        case Accept => acceptPort
        case Return => outDispatcher.inputPort
        case _      => dropPort
      })),

      ///
      /// return dispatcher -> back link ports
      ///
      (0 until backlinks).map(
        i => outDispatcher.outputPort(i) -> backlinkPort(i))
    ).flatten.toMap
  }

  // Set the tag OUT_DISPATCH_TAG_NAME for all jump ports to this chain IVD's
  // index.
  override def compPortInstructions: Map[Port, Instruction] =
    (0 until config.contiguousIVDs.length).map(i => jumpPort(i) ->
      Assign(OUT_DISPATCH_TAG_NAME, ConstantValue(config.index))).toMap
}

/** This is a builder for the 'ChainIVD' class.
 *
 *  In order to build a ChainIVD, besides the name and the chain instance we
 *  want to model, the following must be provided:
 *    * 'index' - it uniquely identifies the chain amongst all chains.
 *    * 'subrules' - this chain's rules split after each rule which has as its
 *    target an user-defined chain.
 *    * 'neighbourChainIndices' - these are the indices of the chains which at
 *    some point might jump to this one; we need them in order to build the
 *    output tag dispatcher, in case a RETURN target is jumped to.
 */
class ChainIVDBuilder(
    name: String,
    chain: Chain,
    index: Int,
    subrules: List[List[Rule]],
    neighbourChainIndices: List[Int])
  extends VirtualDeviceBuilder[ChainIVD](name) { self =>

  override def build: ChainIVD = new ChainIVD(name, new ChainIVDConfig {
    val inDispatcher   =
      InputTagDispatcher(s"$name-in-dispatcher", subrules.length)
    val contiguousIVDs = subrules.zipWithIndex.map {
      case (rules, i) => ContiguousIVD(s"$name-contiguous-$i", rules)
    }
    val outDispatcher  =
      OutputTagDispatcher(s"$name-out-dispatcher", neighbourChainIndices)

    val policy = chain match {
      case bc: BuiltinChain => bc.policy
      case uc: UserChain    => Return
    }

    val index = self.index
  })
}
