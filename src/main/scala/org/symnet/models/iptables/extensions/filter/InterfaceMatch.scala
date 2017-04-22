// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet
package models.iptables
package extensions.filter

import org.change.v2.analysis.expression.concrete.ConstantValue
import org.change.v2.analysis.processingmodels.Instruction
import org.change.v2.analysis.processingmodels.instructions.{:==:, Constrain}

import core._

case class InInterfaceMatch(val interface: String) extends Match {

  override protected def validateIf(
      rule: Rule,
      chain: Chain,
      table: Table): Boolean =
    chain match {
      case BuiltinChain(n, _, _) =>
        List("INPUT", "FORWARD", "PREROUTING") contains n
      case _ => false
    }

  override def seflConstrain(options: SeflGenOptions): Option[Instruction] = {
    import virtdev.InputPortTag
    Some(Constrain(InputPortTag,
                   :==:(ConstantValue(options.portsMap(interface)))))
  }
}

case class OutInterfaceMatch(val interface: String) extends Match {

  override protected def validateIf(
      rule: Rule,
      chain: Chain,
      table: Table): Boolean =
    chain match {
      case BuiltinChain(n, _, _) =>
        List("FORWARD", "OUTPUT", "POSTROUTING") contains n
      case _ => false
    }

  override def seflConstrain(options: SeflGenOptions): Option[Instruction] = {
    import virtdev.OutputPortTag
    Some(Constrain(OutputPortTag,
                   :==:(ConstantValue(options.portsMap(interface)))))
  }
}

object InterfaceMatch extends BaseParsers {
  import ParserMP.monadPlusSyntax._

  def inParser: Parser[Match] =
    for {
      _   <- spacesParser >> oneOf(parseString("-i"),
                                   parseString("--in-interface"))
      neg <- optional(someSpacesParser >> parseChar('!'))
      int <- someSpacesParser >> identifierParser
    } yield Match.maybeNegated(InInterfaceMatch(int), neg)

  def outParser: Parser[Match] =
    for {
      _   <- spacesParser >> oneOf(parseString("-o"),
                                   parseString("--out-interface"))
      neg <- optional(someSpacesParser >> parseChar('!'))
      int <- someSpacesParser >> identifierParser
    } yield Match.maybeNegated(OutInterfaceMatch(int), neg)
}
