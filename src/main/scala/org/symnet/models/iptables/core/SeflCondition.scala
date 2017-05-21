// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet.models.iptables.core

// 3rd-party
// -> Symnet
import org.change.v2.analysis.processingmodels.Instruction
import org.change.v2.analysis.processingmodels.instructions.NoOp

case class SeflCondition(
    constraints: List[Instruction],
    initInstr:   Instruction = NoOp,
    conjunction: Boolean = true)

object SeflCondition {
  def empty: SeflCondition = SeflCondition(Nil)
  def single(
      constraint: Instruction,
      initInstr: Instruction = NoOp): SeflCondition =
    SeflCondition(List(constraint), initInstr)

  def conjunction(
      constraints: List[Instruction],
      initInstr: Instruction = NoOp): SeflCondition =
    SeflCondition(constraints, initInstr, true)
  def disjunction(
      constraints: List[Instruction],
      initInstr: Instruction = NoOp): SeflCondition =
    SeflCondition(constraints, initInstr, false)
}
