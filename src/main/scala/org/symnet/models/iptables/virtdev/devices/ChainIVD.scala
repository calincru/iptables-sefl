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
  val tagDispatcher:  TagReturnDispatcher
  val contiguousIVDs: List[ContiguousIVD]
  val policy:         Policy
  val returnIVD:      Option[ChainIVD]
}

class ChainIVD(
    name:   String,
    config: ChainIVDConfig)
  extends CompositeVirtualDevice[ChainIVDConfig](
    name,
        // 1 input port
    1,
        // n + 2 output ports:
        //  * 0 - ACCEPT output port
        //  * 1 - DROP output port
        //  * [2; n + 2) - jumps to user-defined chains
    config.contiguousIVDs.length + 2,
    config) {

  def inputPort:Port = inputPort(0)
  def acceptPort: Port = outputPort(0)
  def dropPort: Port = outputPort(1)
  def jumpPort(n: Int): Port = outputPort(2 + n)

  // NOTE: We don't add 'returnIVD' (if it exists) because it is a backlink.
  override def devices: List[VirtualDevice[_]] =
    config.contiguousIVDs :+ config.tagDispatcher

  override def newLinks: Map[Port, Port] = {
    val dispatcher = config.tagDispatcher
    val ivds       = config.contiguousIVDs
    val policy     = config.policy
    val returnIVD  = config.returnIVD

    // Link its input to the input of the tag dispatcher.
    Map(inputPort -> dispatcher.inputPort) ++
    // Link dispatcher's outputs to IVDs.
    (0 until ivds.length).map(
      i => dispatcher.outputPort(i) -> ivds(i).inputPort).toMap ++
    // Link IVDs' accept ports to this device's ACCEPT output port
    ivds.map(_.acceptPort -> acceptPort).toMap ++
    // Link IVD' drop ports to this device's DROP output port
    //
    // NOTE: The only reason this is done is to forward all drops to the same
    // port, in case we want to add some common logic at some point.
    ivds.map(_.dropPort -> dropPort).toMap ++
    // Link all IVDs to their corresponding jump ports.
    (0 until ivds.length).map(
      i => ivds(i).jumpPort -> jumpPort(i)).toMap ++
    // Link all IVDs but the last one to the next one.
    (0 until ivds.length - 1).map(
      i => ivds(i).nextIVDport -> ivds(i + 1).inputPort).toMap ++
    // Link the last one according to the policy; we do the following:
    //    * if the policy is Accept, link it to the ACCEPT port of this IVD
    //    * if the policy is Return and there is a chain IVD to return to, link
    //    it to its input port.
    //    * if the policy is Drop OR the policy is return and we are in a
    //    builtin chain (there is no chain to return to), link it to the DROP
    //    port.
    //    * also link to the DROP port in any remaining scenario (the QUEUE
    //    policy)
    Map(ivds.last.nextIVDport -> (
      if (policy == Accept)
        acceptPort
      else if (policy == Return && returnIVD.isDefined)
        returnIVD.get.inputPort
      else
        dropPort
    ))
  }
}

class ChainIVDBuilder(
    name:  String,
    chain: Chain,
    index: IPTIndex) extends VirtualDeviceBuilder[ChainIVD](name) { self =>

  // TODO
  def build: ChainIVD = null
}
