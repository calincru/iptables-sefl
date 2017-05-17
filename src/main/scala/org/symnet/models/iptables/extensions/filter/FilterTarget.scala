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
  type Self <: FilterTarget

  override protected def validateIf(context: ValidationContext): Boolean = {
    val table = context.table.get
    val chain = context.chain.get

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
}

object AcceptTarget extends FilterTarget {
  type Self = this.type

  override def seflCode(options: SeflGenOptions): Instruction =
    Forward(options.acceptPort)
}

object DropTarget extends FilterTarget {
  type Self = this.type

  override def seflCode(options: SeflGenOptions): Instruction =
    Forward(options.dropPort)
}

object ReturnTarget extends FilterTarget {
  type Self = this.type

  override def seflCode(options: SeflGenOptions): Instruction =
    Forward(options.returnPort)
}

object FilterTarget extends BaseParsers {
  def parser: Parser[Target] =
    iptParsers.optionlessTargetParser(Map(("ACCEPT", AcceptTarget),
                                          ("DROP",   DropTarget),
                                          ("RETURN", ReturnTarget)))
}
