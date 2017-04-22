
// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet
package models.iptables
package virtdev

import org.change.v2.analysis.expression.concrete.{ConstantValue, SymbolicValue}
import org.change.v2.analysis.memory.State
import org.change.v2.analysis.memory.TagExp._
import org.change.v2.analysis.processingmodels.instructions._
import org.change.v2.util.canonicalnames._

object SymnetMisc {
  /** The `initial state' as needed by our iptables model. */
  def initState(otherInstr: Instruction): State = InstructionBlock(
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

    // Add here the additional instruction.
    otherInstr,

    CreateTag("END", L4Tag + 12000)
  )(State())._1.head
}
