// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet
package models.iptables

// Scala
import scala.io.Source

// 3rd-party
// -> scalameter
import org.scalameter.api._
import org.scalameter.picklers.noPickler._

// -> Symnet
import org.change.v2.analysis.expression.concrete.ConstantValue
import org.change.v2.analysis.memory.TagExp._
import org.change.v2.analysis.processingmodels.Instruction
import org.change.v2.analysis.processingmodels.instructions._
import org.change.v2.util.canonicalnames._

// project
import extensions.conntrack.ConnectionState
import types.net.Ipv4


object SymbolicExecutionBench extends Bench.ForkedTime {

  // Input
  val testset = Gen.single("model")(List(
    "data/b77-iptables",      // iptables file
    "data/b77-routing-table", // routing table file
    "data/b77-ips",           // ips file
    "qg-09d66f0a-46"          // input port
  ))

  // FIXME: Is there an nicer way of ignoring a test in SBT/scalameter?

  /*
  performance of "Driver" in {
    measure method "symExec" in {
      using (testset) config (
        exec.minWarmupRuns -> 1,
        exec.maxWarmupRuns -> 1,
        exec.benchRuns -> 1,
        exec.independentSamples -> 1
      ) in {
        case List(iptablesFile, routingTableFile, ipsFile, port) => {
          // Get file's contents.
          val List(iptables, routingTable, ips) =
            List(iptablesFile, routingTableFile, ipsFile) map {
              fileName => Source.fromFile(fileName).getLines.mkString("\n")
            }

          // Run the driver.
          new Driver("ipt-router", ips, routingTable, iptables, port) {
            override def initInstruction = InstructionBlock(
              // This is the sane default for any "initial" packet.
              Assign(ctstate, ConstantValue(ConnectionState.New.id)),

              // Constrain the destination IP.
              Assign(IPDst, ConstantValue(Ipv4(8, 8, 8, 8, None).host))
            )
          }.run()
        }
      }
    }
  }
  */
}
