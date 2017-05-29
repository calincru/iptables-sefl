// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet
package models.iptables.virtdev

// 3rd party:
// -> Symnet
import org.change.v2.analysis.expression.concrete._
import org.change.v2.analysis.memory.State
import org.change.v2.analysis.memory.TagExp._
import org.change.v2.analysis.processingmodels.instructions._
import org.change.v2.executor.clickabstractnetwork.ClickExecutionContext
import org.change.v2.executor.clickabstractnetwork.executionlogging.{JsonLogger, NoLogging}
import org.change.v2.util.canonicalnames._

// project
// -> devices
import devices.VirtualDevice

trait SymnetFacade {

  // This has to be overridden by the implementing class.
  def deviceId: String

  ///
  /// Names of device-specific metadata.
  ///

  def nfmark: String = nfmarkTag(deviceId)
  def ctmark: String = ctmarkTag(deviceId)
  def ctstate: String = ctstateTag(deviceId)
  def snatState: String = snatStateTag(deviceId)
  def dnatState: String = dnatStateTag(deviceId)

  ///
  /// Run symbolic execution given a one or more virtual devices
  ///

  def symExec[T <: VirtualDevice[_]](
      vd: T,
      initPort: String,
      otherInstr: Instruction = NoOp,
      otherLinks: Map[Port, Port] = Map.empty,
      log: Boolean = false): (List[State], List[State]) =
    symExec(List(vd), initPort, otherInstr, otherLinks, log)

  def symExec[T <: VirtualDevice[_]](
      vds: List[T],
      initPort: String,
      otherInstr: Instruction,
      otherLinks: Map[Port, Port],
      log: Boolean): (List[State], List[State]) =
    Z3SyncDummyObject.synchronized {
      val model = vds.map(vd => NetworkModel(vd)).reduce(_ ++ _)
      val result = new ClickExecutionContext(
        model.instructions,
        model.links ++ otherLinks,
        List(initState(otherInstr).forwardTo(initPort)),
        Nil,
        Nil,
        logger = if (log) JsonLogger else NoLogging
      ).untilDone(true)

      (result.stuckStates, result.failedStates)
    }

  protected def initState(otherInstr: Instruction): State = InstructionBlock(
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

    Allocate(TcpFlagSYN, 1),
    Allocate(TcpFlagRST, 1),
    Allocate(TcpFlagACK, 1),
    Allocate(TcpFlagFIN, 1),

    CreateTag("END", L4Tag + 12000),

    ///
    /// Metadata fields
    ///

    Allocate(nfmark),
    Assign(nfmark, SymbolicBitVector()),

    Allocate(ctmark),
    Assign(ctmark, SymbolicBitVector()),

    Allocate(ctstate),
    Assign(ctstate, SymbolicValue()),

    Allocate(snatState),
    Assign(snatState, SymbolicValue()),

    Allocate(dnatState),
    Assign(dnatState, SymbolicValue()),

    // Add here the additional instruction.
    otherInstr
  )(State())._1.head
}

private[this] object Z3SyncDummyObject
