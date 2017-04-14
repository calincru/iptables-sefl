// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet.models.iptables.core

import org.change.v2.analysis.processingmodels.Instruction
import org.change.v2.analysis.processingmodels.instructions.{:~:, Constrain, ConstrainNamedSymbol}

import scalaz.Maybe
import scalaz.Maybe._

abstract class Match {

  ///
  /// Validation
  ///

  protected def validateIf(rule: Rule, chain: Chain, table: Table): Boolean =
    true

  def validate(rule: Rule, chain: Chain, table: Table): Maybe[Match] =
    if (validateIf(rule, chain, table))
      Just(this)
    else
      empty

  ///
  /// Sefl code generation
  ///

  /** Generates SEFL constraints corresponding to its semantics. */
  def seflConstrain(options: SeflGenOptions): Instruction
}

case class NegatedMatch(m: Match) extends Match {
  override def validate(rule: Rule, chain: Chain, table: Table): Maybe[Match] =
    m.validate(rule, chain, table)

  override def seflConstrain(options: SeflGenOptions): Instruction =
    m.seflConstrain(options) match {
      case ConstrainNamedSymbol(what, withWhat, _) =>
        Constrain(what, :~:(withWhat))
      case i @ _ => i
    }
}

object Match {
  def maybeNegated[A](m: Match, o: Option[A]): Match =
    if (o.isDefined) NegatedMatch(m) else m
}
