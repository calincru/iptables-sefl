// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet.models.iptables.core

// 3rd-party
// -> Symnet
import org.change.v2.analysis.processingmodels.Instruction

case class SeflCondition(
    constraints: List[Instruction],
    conjunction: Boolean = true)

object SeflCondition {
  def empty: SeflCondition = SeflCondition(Nil)
  def single(constraint: Instruction): SeflCondition =
    SeflCondition(List(constraint))

  def conjunction(constraints: List[Instruction]): SeflCondition =
    SeflCondition(constraints, true)
  def disjunction(constraints: List[Instruction]): SeflCondition =
    SeflCondition(constraints, false)
}
