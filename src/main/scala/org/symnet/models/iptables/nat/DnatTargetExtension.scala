// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet
package models.iptables
package nat

import core._
import types.net.{Ipv4, PortRange}


case class DnatTarget(
    lowerIp:   Ipv4,
    upperIp:   Option[Ipv4],
    portRange: Option[PortRange]) extends Target("DNAT") {

  override protected def validateIf(
      rule: Rule,
      chain: Chain,
      table: Table): Boolean =
    // Check the table/chain in which this target is valid.
    table.name == "nat" &&
      (List("PREROUTING", "OUTPUT") contains chain.name) &&
    // Check that 'tcp' or 'udp' is specified when given the port range.
    //
    // The existance of the port range implies that '-p tcp/udp' must
    // have been specified.
    (portRange.isEmpty || rule.matchesTcpOrUdp)
}

object DnatTarget  {
  import Parsing._
  import Combinators._
  import Parsing.ParserMP.monadPlusSyntax._

  def parser: Parser[Target] =
    for {
      _ <- jumpOptionParser

      // Parse the actual target.
      targetName <- someSpacesParser >> stringParser if targetName == "DNAT"

      // Parse the mandatory '--to-destination' target option.
      _ <- someSpacesParser >> parseString("--to-destination")
      lowerIp <- someSpacesParser >> ipParser

      // Parse the optional upper bound ip.
      upperIp <- optional(parseChar('-') >> ipParser)

      // Parse the optional port range.
      maybePortRange <- optional(parseChar(':') >> portRangeParser)
    } yield DnatTarget(lowerIp, upperIp, maybePortRange)
}

object DnatTargetExtension extends TargetExtension {
  val targetParser = DnatTarget.parser
}
