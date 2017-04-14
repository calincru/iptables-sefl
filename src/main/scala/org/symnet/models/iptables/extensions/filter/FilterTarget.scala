// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet
package models.iptables
package extensions.filter

import org.change.v2.analysis.processingmodels.Instruction
import org.change.v2.analysis.processingmodels.instructions.Forward

import core._

abstract class FilterTarget extends Target {

  override protected def validateIf(
      rule: Rule,
      chain: Chain,
      table: Table): Boolean =
    // The table should be 'filter' ...
    table.name == "filter" &&
    // ... and the chain, if it is a builtin one, should be one of the
    // following
    (chain match {
      case BuiltinChain(name, _, _) =>
        List("INPUT", "FORWARD", "OUTPUT") contains chain.name
      case _ /* UserChain */        => true
    })
}

case object AcceptTarget extends FilterTarget {

  def seflCode(options: SeflGenOptions): Instruction =
    Forward(options.acceptPort)
}

case object DropTarget extends FilterTarget {

  def seflCode(options: SeflGenOptions): Instruction =
    Forward(options.dropPort)
}

case object ReturnTarget extends FilterTarget {

  def seflCode(options: SeflGenOptions): Instruction =
    Forward(options.returnPort)
}

object FilterTarget extends BaseParsers {
  def parser: Parser[Target] =
    iptParsers.optionlessTargetParser(Map(("ACCEPT", AcceptTarget),
                                          ("DROP",   DropTarget),
                                          ("RETURN", ReturnTarget)))
}
