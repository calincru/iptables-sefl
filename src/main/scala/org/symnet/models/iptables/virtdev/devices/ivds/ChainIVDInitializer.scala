// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet
package models.iptables.virtdev
package devices
package ivds

import org.change.v2.analysis.expression.concrete.ConstantValue
import org.change.v2.analysis.expression.concrete.nonprimitive.:@
import org.change.v2.analysis.processingmodels.instructions._
import org.change.v2.util.canonicalnames.{IPDst, IPSrc, TcpDst, TcpSrc}

import models.iptables.core.{Chain, Table}

// TODO: A `Chain' should probably suffice if we re-design it.
trait ChainIVDInitializerConfig {
  val id:    String
  val chain: Chain
  val table: Table
}

case class ChainIVDInitializer(
    name:   String,
    config: ChainIVDInitializerConfig)
  extends RegularVirtualDevice[ChainIVDInitializerConfig](
    name,
      // one input port
    1,
      // two output ports:
      //  * 0 - continue
      //  * 1 - skip
    2,
    config) {

  def inputPort:  Port = inputPort(0)

  def continuePort: Port = outputPort(0)
  def skipPort:     Port = outputPort(1)

  override def portInstructions: Map[Port, Instruction] = {
    val snatOrigSrc = snatFromIp(config.id)
    val snatOrigPort = snatFromPort(config.id)
    val snatNewSrc = snatToIp(config.id)
    val snatNewPort = snatToPort(config.id)

    val dnatOrigDst = dnatFromIp(config.id)
    val dnatOrigPort = dnatFromPort(config.id)
    val dnatNewDst = dnatToIp(config.id)
    val dnatNewPort = dnatToPort(config.id)

    List(
      Map(inputPort -> InstructionBlock(
        // Generate code for NAT handling.
        if (config.table.name == "nat") {
          if (config.chain.name == "PREROUTING") {
            InstructionBlock(
              // Reuse existing DNAT mapping.
              If(Constrain(IPDst, :==:(:@(dnatOrigDst))),
                 If(Constrain(TcpDst, :==:(:@(dnatOrigPort))),
                    InstructionBlock(
                      Assign(IPDst, :@(dnatNewDst)),
                      Assign(TcpDst, :@(dnatNewPort)),
                      Forward(skipPort)),
                    NoOp),
                 NoOp),

              // Rewrite dst in a reply to a SNAT'ed packet.
              // TODO: Should this still go through the chain?
              If(Constrain(IPDst, :==:(:@(snatNewSrc))),
                 If(Constrain(TcpDst, :==:(:@(snatNewPort))),
                    InstructionBlock(
                      Assign(IPDst, :@(snatOrigSrc)),
                      Assign(TcpDst, :@(snatOrigPort)),
                      Forward(skipPort)),
                    NoOp),
                 NoOp)
            )
          } else if (config.chain.name == "POSTROUTING") {
            InstructionBlock(
              // Reuse existing SNAT mapping.
              If(Constrain(IPSrc, :==:(:@(snatOrigSrc))),
                 If(Constrain(TcpSrc, :==:(:@(snatOrigPort))),
                    InstructionBlock(
                      Assign(IPSrc, :@(snatNewSrc)),
                      Assign(TcpSrc, :@(snatNewPort)),
                      Forward(skipPort)),
                    NoOp),
                 NoOp),

              // Rewrite src in a reply to a DNAT'ed packet.
              // TODO: Should this still go through the chain?
              If(Constrain(IPSrc, :==:(:@(dnatNewDst))),
                 If(Constrain(TcpSrc, :==:(:@(dnatNewPort))),
                    InstructionBlock(
                      Assign(IPSrc, :@(dnatOrigDst)),
                      Assign(TcpSrc, :@(dnatOrigPort)),
                      Forward(skipPort)),
                    NoOp),
                 NoOp)
            )
          } else {
            NoOp
          }
        } else {
          NoOp
        },

        // Initialize the input dispatch tag: allocate a new one and initialize
        // it to zero.
        Allocate(InputDispatchTag),
        Assign(InputDispatchTag, ConstantValue(0)),
        Forward(continuePort))),

      Map(skipPort -> Fail(s"Packet skipped by $name"))
    ).flatten.toMap
  }
}
