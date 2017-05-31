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

  class StatesContainPath(ports: List[Interface]) extends Matcher[List[State]] {

    def apply(states: List[State]) =
      MatchResult(
        states.exists(_.history == ports.reverse),
        s"""There is no state which passes through the given ports ($ports)""",
        s"""There is a state which passes through the given ports"""
      )
  }

  class StatesPassThrough(ports: List[Interface]) extends Matcher[List[State]] {

    def apply(states: List[State]) =
      MatchResult(
        states.exists(s => {
          val history = s.history.reverse
          val indices = ports.map(p => history.indexOf(p))

          !indices.contains(-1) && indices == indices.sorted
        }),
        s"""No state passes through the given ports in order ($ports)""",
        s"""There is a state which passes through the given ports in order"""
      )
  }

  class StatesReachPort(port: Interface) extends Matcher[List[State]] {

    def apply(states: List[State]) =
      MatchResult(
        states.exists(_.history.head == port),
        s"""No state ends in given port $port""",
        s"""There is a state which ends in the given port $port"""
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
        s"""Constrain $c not found""",
        s"""Constrain $c found"""
      )
    }

  ///
  /// Factory functions.
  ///

  def containPath(ports: Interface*) = new StatesContainPath(ports.toList)
  def passThrough(ports: Interface*) = new StatesPassThrough(ports.toList)
  def reachPort(port: Interface) = new StatesReachPort(port)

  def containConstrain(constrain: Instruction) =
    new StatesContainConstrain(constrain)
}
