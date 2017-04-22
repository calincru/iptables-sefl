
// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet
package models.iptables
package virtdev

// 3rd party:
// -> Symnet
import org.change.v2.analysis.expression.concrete.{ConstantValue, SymbolicValue}
import org.change.v2.analysis.memory.State
import org.change.v2.analysis.memory.TagExp._
import org.change.v2.analysis.processingmodels.instructions._
import org.change.v2.executor.clickabstractnetwork.ClickExecutionContext
import org.change.v2.executor.clickabstractnetwork.executionlogging.JsonLogger
import org.change.v2.util.canonicalnames._

// project
// -> virtdev
import virtdev.{NetworkModel => Model}
import virtdev.devices.VirtualDevice

object SymnetMisc {

  def symExec[T <: VirtualDevice[_]](
      vd: T,
      initPort: String,
      otherInstr: Instruction = NoOp) = {
    val model = Model(vd)
    val result = new ClickExecutionContext(
      model.instructions,
      model.links,
      List(initState(otherInstr).forwardTo(initPort)),
      Nil,
      Nil,
      logger = JsonLogger).untilDone(true)

    (result.stuckStates, result.failedStates)
  }

  private def initState(otherInstr: Instruction): State = InstructionBlock(
    CreateTag("START",0),
    CreateTag("L3", 0),

    Allocate(Proto, 8),
    Assign(Proto, SymbolicValue()),

    Allocate(IPSrc, 32),
    Assign(IPSrc, SymbolicValue()),

    Allocate(IPDst, 32),
    Assign(IPDst, SymbolicValue()),

    CreateTag("L4", L3Tag + 160),

    Allocate(TcpSrc, 16),
    Assign(TcpSrc, SymbolicValue()),

    Allocate(TcpDst, 16),
    Assign(TcpDst, SymbolicValue()),

    CreateTag("END", L4Tag + 12000),

    // Add here the additional instruction.
    otherInstr
  )(State())._1.head
}
