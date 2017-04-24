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
import extensions.nat.{SnatTargetExtension}

object VirtdevSuitesCommon {
  val portsMap = Map("eth0" -> 0, "eth1" -> 1, "eth2" -> 2)

  private implicit def parsingContext = new ParsingContext {
    override val matchExtensions  =
      List(FilteringExtension)
    override val targetExtensions =
      List(SnatTargetExtension,
           FilteringExtension,
           ChainTargetExtension)
  }

  def toRule(ruleStr: String) = ruleParser.eval(ruleStr).toOption.get
  def toChain(chainStr: String) = chainParser.eval(chainStr).toOption.get
  def toTable(tableStr: String) =
    tableParser.eval(tableStr).flatMap(_.validate).toOption.get
}
