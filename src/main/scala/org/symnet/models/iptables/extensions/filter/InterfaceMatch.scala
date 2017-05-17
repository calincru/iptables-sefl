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

case class InInterfaceMatch(interface: String, regex: Boolean) extends Match {
  type Self = InInterfaceMatch

  override protected def validateIf(context: ValidationContext): Boolean = {
    val chain = context.chain.get

    chain match {
      case BuiltinChain(n, _, _) =>
        List("INPUT", "FORWARD", "PREROUTING") contains n
      case _ /* UserChain */ => true
    }
  }

  override def seflConstrain(options: SeflGenOptions): Option[Instruction] = {
    import virtdev.InputPortTag
    Some(Constrain(InputPortTag,
                   :==:(ConstantValue(options.portsMap(interface)))))
  }
}

case class OutInterfaceMatch(interface: String, regex: Boolean) extends Match {
  type Self = OutInterfaceMatch

  override protected def validateIf(context: ValidationContext): Boolean = {
    val chain = context.chain.get

    chain match {
      case BuiltinChain(n, _, _) =>
        List("FORWARD", "OUTPUT", "POSTROUTING") contains n
      case _ /* UserChain */ => true
    }
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
      _  <- spacesParser
      n1 <- optional(parseChar('!') >> someSpacesParser)
      _  <- oneOf(parseString("-i"), parseString("--in-interface"))
      n2 <- conditional(optional(someSpacesParser >> parseChar('!')),
                        !n1.isDefined)
      int <- someSpacesParser >> identifierParser
      maybePlus <- optional(parseChar('+'))
    } yield Match.maybeNegated(
      InInterfaceMatch(int, maybePlus.isDefined), n1 orElse n2.flatten)

  def outParser: Parser[Match] =
    for {
      _  <- spacesParser
      n1 <- optional(parseChar('!') >> someSpacesParser)
      _  <- oneOf(parseString("-o"), parseString("--out-interface"))
      n2 <- conditional(optional(someSpacesParser >> parseChar('!')),
                        !n1.isDefined)
      int <- someSpacesParser >> identifierParser
      maybePlus <- optional(parseChar('+'))
    } yield Match.maybeNegated(
      OutInterfaceMatch(int, maybePlus.isDefined), n1 orElse n2.flatten)
}
