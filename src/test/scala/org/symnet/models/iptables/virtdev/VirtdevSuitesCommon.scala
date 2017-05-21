// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet
package models.iptables
package virtdev

// 3rd-party
// -> Symnet
import org.change.v2.analysis.memory.State

// project
// -> core
import core._
import iptParsers.{chainParser, ruleParser, tableParser}

// -> devices
import devices.VirtualDevice

// -> extensions
import extensions.filter.FilteringExtension
import extensions.nat._
import extensions.tcp.TcpExtension
import extensions.udp.UdpExtension
import extensions.mark.MarkMatchExtension

object VirtdevSuitesCommon {
  val portsMap = Map("eth0" -> 0, "eth1" -> 1, "eth2" -> 2)

  // TODO: Remove the extensions once the module loading works.
  private implicit def parsingContext =
    ParsingContext
      .default
      .addMatchExtension(TcpExtension)
      .addMatchExtension(UdpExtension)
      .addMatchExtension(MarkMatchExtension)

  def toRule(ruleStr: String) = {
    val maybeResult = ruleParser.apply(ruleStr).toOption
    assert(maybeResult.isDefined)

    val (state, result) = maybeResult.get
    assert(state.trim.isEmpty)

    result
  }

  def toChain(chainStr: String) = {
    val maybeResult = chainParser.apply(chainStr).toOption
    assert(maybeResult.isDefined)

    val (state, result) = maybeResult.get
    assert(state.trim.isEmpty)

    result
  }

  def toTable(tableStr: String) = {
    val maybeResult = tableParser.apply(tableStr).toOption
    assert(maybeResult.isDefined)

    val (state, result) = maybeResult.get
    assert(state.trim.isEmpty)

    val validatedResult = result.validate(
      ValidationContext.empty.setInterfaces(portsMap.keys.toList)).toOption
    assert(validatedResult.isDefined)

    validatedResult.get
  }

  /** These functions ease testing against failing/accepted states, as we are
   *  sometimes only interested in those which were caused by explicitly
   *  dropping/accepting the packet.
   *
   *  FIXME: It is assumed that the `acceptPort' is `outputPort(0)' and
   *  `dropPort' is `outputPort(1)'.
   */
  def accepted[T <: VirtualDevice[_]](successfulStates: List[State], t: T) =
    successfulStates.filter(_.history.head == t.outputPort(0))

  def dropped[T <: VirtualDevice[_]](failStates: List[State], t: T) =
    failStates.filter(_.history.head == t.outputPort(1))
}
