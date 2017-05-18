// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet
package models.iptables
package virtdev

// project
// -> core
import core._
import iptParsers.{chainParser, ruleParser, tableParser}

// -> extensions
import extensions.filter.FilteringExtension
import extensions.nat._
import extensions.tcp.TcpExtension
import extensions.udp.UdpExtension

object VirtdevSuitesCommon {
  val portsMap = Map("eth0" -> 0, "eth1" -> 1, "eth2" -> 2)

  // TODO: Remove the extensions once the module loading works.
  private implicit def parsingContext =
    ParsingContext
      .default
      .addMatchExtension(TcpExtension)
      .addMatchExtension(UdpExtension)

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

    val validatedResult = result.validate(ValidationContext.empty).toOption
    assert(validatedResult.isDefined)

    validatedResult.get
  }
}
