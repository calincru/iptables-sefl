// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet
package models.iptables.virtdev
package devices
package ivds

import org.change.v2.analysis.expression.concrete.ConstantValue
import org.change.v2.analysis.processingmodels.instructions.{Assign, Allocate, Fail, InstructionBlock}

import models.iptables.core._
import Policy._

trait ChainIVDConfig {
  // IVDs
  val initializer:    ChainIVDInitializer
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
        // 2 input ports:
        //  * 0 - regular input port
        //  * 1 - initializer input port (see below for use case)
    2,
        // (2 + n + m) output ports:
        //  * 0 - ACCEPT output port
        //  * 1 - DROP output port
        //  * [2; 2 + n) - jumps to user-defined chains
        //  * [2 + n; 2 + n + m) - backlinks
    2 + config.contiguousIVDs.length + config.outDispatcher.outputPorts,
    config) {

  // Briefly, the input port is used only when returning from a user-defined
  // chain to which a jump from this one has been made, to ensure that the
  // previous value of the input dispatch tag is seen.
  //
  // TODO: Consider renaming them.
  def initPort: Port = inputPort(0)
  def inputPort: Port = inputPort(1)

  def acceptPort: Port = outputPort(0)
  def dropPort: Port = outputPort(1)
  def jumpPort(n: Int): Port = outputPort(2 + n)
  def backlinkPort(n: Int): Port =
    outputPort(2 + config.contiguousIVDs.length + n)

  protected override def devices: List[VirtualDevice[_]] =
    config.contiguousIVDs ++
    List(config.initializer, config.inDispatcher, config.outDispatcher)

  protected override def newLinks: Map[Port, Port] = {
    val initializer   = config.initializer
    val inDispatcher  = config.inDispatcher
    val ivds          = config.contiguousIVDs
    val outDispatcher = config.outDispatcher
    val policy        = config.policy
    val backlinks     = config.outDispatcher.outputPorts

    // This is the port towards to packets are forwarded when no rule matches.
    val defaultPort = policy match {
      case Accept => acceptPort
      case Return => outDispatcher.inputPort
      // NOTE: This case also includes the QUEUE policy.
      case _      => dropPort
    }

    List(
      ///
      /// initPort -> initializer -> input
      ///
      Map(initPort                 -> initializer.inputPort,
          initializer.continuePort -> inputPort,
          initializer.skipPort     -> acceptPort),

      ///
      /// input -> tag dispatcher
      ///
      Map(inputPort -> inDispatcher.inputPort),

      ///
      /// tag dispatcher -> IVDs
      ///
      // Link input tag dispatcher's outputs to IVDs.
      (0 until ivds.length).map(
        i => inDispatcher.outputPort(i) -> ivds(i).inputPort),

      // The input dispatcher has its last output port reserved for a special
      // case (described in the builder below).
      Map(inDispatcher.outputPort(ivds.length) -> defaultPort),

      ///
      /// Setup output ports for IVDs
      ///
      // Link IVDs' accept ports to this device's ACCEPT output port
      ivds.map(_.acceptPort -> acceptPort),

      // Link all IVDs to the port controlling RETURNs.
      //
      // NOTE: If there are no backlinks, this must be a built-in chain and the
      // default policy should be applied. Also, in this case, the default
      // policy *should not* be RETURN.
      ivds.map(_.returnPort ->
        (if (backlinks == 0) defaultPort else outDispatcher.inputPort)),

      // Link all IVDs to their corresponding jump ports.
      (0 until ivds.length).map(
        i => ivds(i).jumpPort -> jumpPort(i)),

      // Link all IVDs but the last one to the next one.
      (0 until ivds.length - 1).map(
        i => ivds(i).nextIVDport -> ivds(i + 1).inputPort),

      // Link the last one according to the policy.
      if (!ivds.isEmpty) {
        Map(ivds.last.nextIVDport -> defaultPort)
      } else {
        Map()
      },

      ///
      /// return dispatcher -> back link ports
      ///
      (0 until backlinks).map(
        i => outDispatcher.outputPort(i) -> backlinkPort(i))
    ).flatten.toMap
  }

  protected override def compPortInstructions: Map[Port, Instruction] =
    List(
      // Add instructions on jump ports.
      (0 until config.contiguousIVDs.length).map(i => jumpPort(i) ->
        InstructionBlock(
          // Push the index of this chain IVD on the stack corresponding to the
          // output dispatch tag.
          Allocate(OutputDispatchTag),
          Assign(OutputDispatchTag, ConstantValue(config.index)),

          // Push the index of the successor of the contiguous chain IVD which
          // caused this jump on the stack corresponding to the input dispatch
          // tag.
          //
          // TODO: Is there a way to clear the entire stack before doing this?
          // It's not guaranteed we will return to have this consumed by the
          // input dispatcher.
          Allocate(InputDispatchTag),
          Assign(InputDispatchTag, ConstantValue(i + 1))
        )
      ),

      // Fail if the drop port is reached.
      Map(dropPort -> Fail(s"Packet dropped by $name"))
    ).flatten.toMap
}

/** This is a builder for the 'ChainIVD' class.
 *
 *  In order to build a ChainIVD, besides the name and the chain instance we
 *  want to model, the following must be provided:
 *    * `index' - it uniquely identifies the chain amongst all chains.
 *    * `subrules' - this chain's rules split after each rule which has as its
 *    target a user-defined chain.
 *    * `neighbourChainIndices' - these are the indices of the chains which at
 *    some point might jump to this one; we need them in order to build the
 *    output tag dispatcher, in case a RETURN target is jumped to.
 *    * `portsMap' - a map from real port names of the device being modeled to
 *    port indices of the model.
 */
class ChainIVDBuilder(
    name: String,
    chain: Chain,
    table: Table,
    index: Int,
    subrules: List[List[Rule]],
    neighbourChainIndices: List[Int],
    portsMap: Map[String, Int])
  extends VirtualDeviceBuilder[ChainIVD](name) { self =>

  override def build: ChainIVD = new ChainIVD(name, new ChainIVDConfig {
    val initializer =
      ChainIVDInitializer(s"$name-initializer", new ChainIVDInitializerConfig {
        // TODO: Shouldn't `id' be the name of the whole device?
        val id = self.name
        val chain = self.chain
        val table = self.table
      })

    // NOTE: The '+ 1' here is to handle the case when the last rule is a jump
    // to a user-defined chain.  If it returns back to the calling contiguous
    // IVD, we have to be able to do something with that packet; in this case,
    // to apply the default policy of this Chain IVD.
    val inDispatcher =
      InputTagDispatcher(s"$name-in-dispatcher", subrules.length + 1)

    val contiguousIVDs = subrules.zipWithIndex.map {
      case (rules_, i) =>
        ContiguousIVD(s"$name-contiguous-$i", new ContiguousIVDConfig {
          // TODO: Shouldn't `id' be the name of the whole device?
          val id = self.name
          val rules = rules_
          val portsMap = self.portsMap
        })
    }

    val outDispatcher =
      OutputTagDispatcher(s"$name-out-dispatcher", neighbourChainIndices)

    val policy = chain match {
      case bc: BuiltinChain => bc.policy

      // NOTE: This is not officially documented (i.e. a packet shouldn't reach
      // the end of a user-defined chain).
      case uc: UserChain    => Return
    }

    val index = self.index
  })
}
