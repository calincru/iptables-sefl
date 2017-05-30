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

object SymbolicExecutionBench extends Bench.LocalTime {

  val testset = Gen.single("model")(List(
    "data/b77-iptables",      // iptables file
    "data/b77-routing-table", // routing table file
    "data/b77-ips",           // ips file
    "qg-09d66f0a-46"          // input port
  ))

  performance of "Driver" in {
    measure method "symExec" in {
      using (testset) in {
        case List(iptablesFile, routingTableFile, ipsFile, port) => {
          // Get file's contents.
          val List(iptables, routingTable, ips) =
            List(iptablesFile, routingTableFile, ipsFile) map {
              fileName => Source.fromFile(fileName).getLines.mkString("\n")
            }

          // Run the driver.
          // new Driver(
          //   ips,
          //   routingTable,
          //   iptables,
          //   validateOnly=false,
          //   inputPort=port).run()
        }
      }
    }
  }
}
