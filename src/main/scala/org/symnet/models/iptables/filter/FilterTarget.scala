// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet
package models.iptables
package filter

import core._

class FilterTarget(name: String) extends Target(name) {

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

case object AcceptTarget extends FilterTarget("ACCEPT")

case object DropTarget   extends FilterTarget("DROP")

case object ReturnTarget extends FilterTarget("RETURN")

object FilterTarget extends BaseParsers {
  def parser: Parser[Target] =
    iptParsers.optionlessTargetParser(Map(("ACCEPT", AcceptTarget),
                                          ("DROP",   DropTarget),
                                          ("RETURN", ReturnTarget)))
}
