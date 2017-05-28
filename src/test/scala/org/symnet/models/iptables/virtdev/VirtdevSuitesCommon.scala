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

// -> ivd
import devices.ivds.IptablesVirtualDevice

// -> extensions
import extensions.filter.FilteringExtension
import extensions.nat._

object VirtdevSuitesCommon {
  val portsMap = Map("eth0" -> 0, "eth1" -> 1, "eth2" -> 2)

  private implicit def parsingContext = ParsingContext.default

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
   */
  def accepted(successfulStates: List[State], ivd: IptablesVirtualDevice[_]) =
    successfulStates.filter(_.history.head == ivd.acceptPort)

  def dropped(failStates: List[State], ivd: IptablesVirtualDevice[_]) =
    failStates.filter(_.history.head == ivd.dropPort)
}
