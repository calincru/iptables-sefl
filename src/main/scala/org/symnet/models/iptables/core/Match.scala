// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet.models.iptables.core

import org.change.v2.analysis.processingmodels.Instruction
import org.change.v2.analysis.processingmodels.instructions.{:~:, Constrain, ConstrainNamedSymbol, ConstrainRaw}

import scalaz.Maybe
import scalaz.Maybe._

trait Match extends IptElement {
  type Self <: Match

  /** A match could enable other match extensions.  This method returns them as
   *  a list.
   */
  def extensionsEnabled: List[MatchExtension] = Nil

  ///
  /// Sefl code generation
  ///

  /** Generates SEFL constraints corresponding to its semantics.
   *
   *  NOTE: A simple conjunction/disjunction suffices for now.
   */
  def seflCondition(options: SeflGenOptions): SeflCondition
}

trait ModuleLoaderMatch extends Match {
  final override def seflCondition(
      options: SeflGenOptions): SeflCondition = SeflCondition.empty
}

case class NegatedMatch(m: Match) extends Match {
  type Self = NegatedMatch

  override def validate(context: ValidationContext): Maybe[NegatedMatch] =
    m.validate(context).map(vM => NegatedMatch(vM))

  override def seflCondition(options: SeflGenOptions): SeflCondition = {
    // Take the original condition.
    val mCondition = m.seflCondition(options)

    // Negate all constraints.
    val newConstraints = mCondition.constraints.map(i => i match {
      // Duplicate code, not nice :(.
      case ConstrainNamedSymbol(what, withWhat, _) =>
        Constrain(what, :~:(withWhat))
      case ConstrainRaw(what, withWhat, _) =>
        Constrain(what, :~:(withWhat))

      case i @ _ => i
    })

    // (De Morgan's law) Group them using the opposite logic operation.
    SeflCondition(newConstraints, mCondition.initInstr, !mCondition.conjunction)
  }
}

object Match {
  def maybeNegated[A](m: Match, o: Option[A]): Match =
    if (o.isDefined) NegatedMatch(m) else m
}
