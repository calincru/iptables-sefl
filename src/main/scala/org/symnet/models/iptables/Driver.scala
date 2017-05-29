// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet
package models.iptables

// Scala
import scala.io.Source

// 3rd-party
// -> scallop
import org.rogach.scallop._

// project
import core.{iptParsers, BaseParsers, ParsingContext}
import types.net.Ipv4

class Driver(
    ipsStr: String,
    routingTableStr: String,
    iptablesStr: String,
    validateOnly: Boolean) extends BaseParsers {

  private def parse[T](p: Parser[T], s: String): T = {
    val maybeResult = p.apply(s)
    assert(maybeResult.isJust)

    val (state, result) = maybeResult.toOption.get
    println(state)
    assert(state.trim.isEmpty)

    result
  }

  def run() = {
    // Parse ips.
    val ipsMap = ipsStr.split("\n").map(line => {
      val tokens = line.split(" ")
      val int = parse(identifierParser, tokens(0))
      // FIXME: Multiple ips on an interface.
      (int, parse(ipParser, tokens(1)))
    }).toMap

    // Parse routing table.
    val routingTable = routingTableStr.split("\n").map(line => {
        val Array(ipStr, nextHop) = line.split(" ")
        (parse(ipParser, ipStr), parse(identifierParser, nextHop))
    })

    // Parse iptables.
    val iptables = {
      implicit val parsingContext = ParsingContext.default
      parse(many(iptParsers.tableParser), iptablesStr)
    }

    // TODO: Validate and run symbolic execution.
  }
}

object Driver extends App {
  class Conf(arguments: Seq[String]) extends ScallopConf(arguments) {
    val iptables = opt[String](required=true)
    val routing_table = opt[String](required=true)
    val ips = opt[String](required=true)
    val validate_only = opt[Boolean]()
    verify()
  }
  val conf = new Conf(args)

  val List(iptables, routingTable, ips) =
    List(conf.iptables(), conf.routing_table(), conf.ips()) map {
      fileName => Source.fromFile(fileName).getLines.mkString("\n")
    }

  new Driver(
    ipsStr = ips,
    routingTableStr = routingTable,
    iptablesStr = iptables,
    validateOnly = conf.validate_only()
  ).run()
}
