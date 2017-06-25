// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet
package models.iptables
package perf

// Scala
import scala.io.Source
import scala.util.Random

// 3rd party:
// -> Symnet
import org.change.v2.analysis.expression.concrete.ConstantValue
import org.change.v2.analysis.processingmodels.instructions.{Assign, InstructionBlock}
import org.change.v2.util.canonicalnames.IPDst

// -> scallop
import org.rogach.scallop._

// project
import core.BaseParsers
import types.net.Ipv4
import virtdev.SymnetFacade

object NetworkDepthTest extends App with SymnetFacade with BaseParsers {

  /////////////////////////////////////////
  /// Parse args
  /////////////////////////////////////////

  class Conf(arguments: Seq[String]) extends ScallopConf(arguments) {
    val chains_no = opt[Int](required = true)
    val chain_size = opt[Int](required = true)
    val destination_ip = opt[String](default = Some("8.8.8.8"))
    verify()
  }
  val conf = new Conf(args)

  /////////////////////////////////////////
  /// Local variables & utility functions
  /////////////////////////////////////////

  override def deviceId = "network-depth-test"

  private val rt = """
    192.168.0.0/24 eth1
    0.0.0.0/0 eth0
  """
  private val ips = """
    eth0 15.15.15.15
    eth1 192.168.0.1
  """

  private val allIndices = (0 until conf.chains_no()).toList
  private val inputPort = "eth0"

  private def getConfFile(size: Int, nth: Int) = {
    val rootDir = "data/generated"
    val confFile = s"$rootDir/$size/_gen$nth"
    Source.fromFile(confFile).getLines.mkString("\n")
  }

  private def getDriver(name: String, conf: String) = {
    new Driver(name, ips, rt, conf, "unused")
  }

  /////////////////////////////////////////
  /// Run the test for each depth
  /////////////////////////////////////////

  List(2) map { depth =>
    val indices = Random.shuffle(allIndices).take(depth)
    val drivers = indices.map(i =>
        getDriver(s"ipt$i", getConfFile(conf.chain_size(), i)))
    val iptRouters = drivers.map(_.iptRouter)

    val t0 = System.nanoTime()
    val (successful, failed) = symExec(
      vds = iptRouters,
      // We start from the first device and go forward.
      initPort = iptRouters.head.inputPort(inputPort),
      // We need to do two things:
      //    1. Set destination IP to a concrete value.
      //    2. Add the metadata init instructions for each device.
      otherInstr = InstructionBlock(
        Assign(IPDst,
          ConstantValue(Driver.parse(ipParser, conf.destination_ip()).host)) +:
        drivers.map(_.metadataInitInstr)),
      // Link them together to form the actual network topology.
      otherLinks = (0 until depth - 1).map(i =>
          iptRouters(i).outputPort("eth0") ->
            iptRouters(i + 1).inputPort("eth0")).toMap,
      log = true
    )
    val t1 = System.nanoTime()

    println("*********** STATS BEGIN HERE ***********")
    println(s"Time (depth = ${depth}): ${(t1 - t0) / 1000000000.0}")
    println(s"Successful paths: ${successful.size}")
    println(s"Failed paths: ${failed.size}")
    println("*********** STATS END HERE ***********")
  }
}
