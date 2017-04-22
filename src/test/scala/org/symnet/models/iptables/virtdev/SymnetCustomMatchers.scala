
// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet
package models.iptables
package virtdev

// 3rd party:
// -> scalatest
import org.scalatest._
import matchers._

// -> Symnet
import org.change.v2.analysis.memory.{Intable, State}
import org.change.v2.analysis.processingmodels.instructions._

// project
// -> virtdev
import virtdev.{Port => Interface}

trait SymnetCustomMatchers {

  class StatesContainPath(ports: Interface*)
    extends Matcher[List[State]] {

    def apply(states: List[State]) =
      MatchResult(
        states.exists(_.history == ports.toList.reverse),
        s"""There is no state in $states which passed through ports $ports""",
        s"""There is a state in $states which passed through ports $ports"""
      )
  }

  class StatesContainConstrain(c: Instruction) extends Matcher[List[State]] {

    // TODO: Make sure it always works.
    def apply(states: List[State]) =
      MatchResult(
        c match {
          case cns @ ConstrainNamedSymbol(what, withWhat, _) =>
            states.exists(s => withWhat.instantiate(s) match {
              case Left(eCst) => s.memory.eval(what) match {
                case Some(eVal) => eVal.cts.contains(eCst)
                case None => false
              }
              case Right(_) => false
            })

          case cni @ ConstrainRaw(what, withWhat, _) =>
            states.exists(s => (what(s), withWhat.instantiate(s)) match {
              case (Some(eVar), Left(eCst)) => s.memory.eval(eVar) match {
                case Some(eVal) => eVal.cts.contains(eCst)
                case None => false
              }
              case _ => false
            })

          case _ => false
        },
        s"""Constrain $c found""",
        s"""Constrain $c not found"""
      )
    }

  ///
  /// Factory functions.
  ///

  def containPath(ports: Interface*) = new StatesContainPath(ports: _*)

  def containConstrain(constrain: Instruction) =
    new StatesContainConstrain(constrain)
}
