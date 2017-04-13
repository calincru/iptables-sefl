// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet
package models.iptables.virtdev
package devices

import models.iptables.core.{Chain, IPTIndex, Policy}
import Policy._

trait ChainIVDConfig {
  // IVDs
  val tagDispatcher:    InputTagDispatcher
  val contiguousIVDs:   List[ContiguousIVD]
  val returnDispatcher: OutputTagDispatcher

  // The default policy of the chain modelled by this IVD.
  val policy: Policy

  // IVDs which jump to this one.
  val backlinks: List[ChainIVD]
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
    2 + config.contiguousIVDs.length + config.backlinks.length,
    config) {

  def inputPort:Port = inputPort(0)
  def acceptPort: Port = outputPort(0)
  def dropPort: Port = outputPort(1)
  def jumpPort(n: Int): Port = outputPort(2 + n)
  def backlinkPort(n: Int): Port =
    outputPort(2 + config.contiguousIVDs.length + n)

  override def devices: List[VirtualDevice[_]] =
    config.contiguousIVDs :+ config.tagDispatcher

  override def newLinks: Map[Port, Port] = {
    val tagDispatcher    = config.tagDispatcher
    val ivds             = config.contiguousIVDs
    val returnDispatcher = config.returnDispatcher
    val policy           = config.policy

    ///
    /// input -> tag dispatcher
    ///
    Map(inputPort -> tagDispatcher.inputPort) ++
    ///
    /// tag dispatcher -> IVDs
    ///
    // Link tag dispatcher's outputs to IVDs.
    (0 until ivds.length).map(
      i => tagDispatcher.outputPort(i) -> ivds(i).inputPort).toMap ++
    ///
    /// Setup output ports for IVDs
    ///
    // Link IVDs' accept ports to this device's ACCEPT output port
    ivds.map(_.acceptPort -> acceptPort).toMap ++
    // Link IVD' drop ports to this device's DROP output port
    //
    // NOTE: The only reason this is done is to forward all drops to the same
    // port, in case we want to add some common logic at some point.
    ivds.map(_.dropPort -> dropPort).toMap ++
    // Link all IVDs to the port controlling RETURNs.
    ivds.map(_.returnPort -> returnDispatcher.inputPort).toMap ++
    // Link all IVDs to their corresponding jump ports.
    (0 until ivds.length).map(
      i => ivds(i).jumpPort -> jumpPort(i)).toMap ++
    // Link all IVDs but the last one to the next one.
    (0 until ivds.length - 1).map(
      i => ivds(i).nextIVDport -> ivds(i + 1).inputPort).toMap ++
    // Link the last one according to the policy.
    Map(ivds.last.nextIVDport -> (policy match {
      case Accept => acceptPort
      case Return => returnDispatcher.inputPort
      case _      => dropPort
    })) ++
    ///
    /// return dispatcher -> output back links
    ///
    // TODO: Add these.
    Map()
  }
}

class ChainIVDBuilder(
    name:  String,
    chain: Chain,
    index: IPTIndex) extends VirtualDeviceBuilder[ChainIVD](name) { self =>

  // TODO
  def build: ChainIVD = null
}
