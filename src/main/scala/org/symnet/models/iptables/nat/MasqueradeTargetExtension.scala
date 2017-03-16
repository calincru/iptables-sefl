// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet
package models.iptables
package filter

import core._
import types.net.{Ipv4, Port}


case class MasqueradeTarget(
    lowerPort: Option[Port],
    upperPort: Option[Port]) extends Target("MASQUERADE") {

  /** This target is only valid in the 'nat' table, in the 'POSTROUTING'
   *  chain.
   *
   *  The '--to-ports' option is only valid if the rule also specifies
   *  '-p tcp' or '-p udp'.
   */
  override protected def validateIf(
      rule: Rule,
      chain: Chain,
      table: Table): Boolean = {
    // Check the table/chain in which this target is valid.
    table.name == "nat" && chain.name == "POSTROUTING" &&
    // The existance of the upper port implies the existance of the lower
    // one.
    //
    //      upperPort -> lowerPort <=> !upperPort or lowerPort
    //
    (upperPort.isEmpty || lowerPort.isDefined)
    // Check that 'tcp' or 'udp' is specified when either of the lower/upper
    // ports are given.
    //
    // The existance of any of the lower/upper ports implies that '-p
    // tcp/udp' must have been specified.
    //
    //      lowerPort or upperPort -> tcp/udp
    // but  upperPort -> lowerPort =>
    // =>   lowerPort -> tcp/udp  <=> !lowerPort or tcp/udp
    //
    (lowerPort.isEmpty || rule.matchesTcpOrUdp)
  }
}

object MasqueradeTarget {
  import Parsing._
  import Combinators._
  import Parsing.ParserMP.monadPlusSyntax._

  def parser: Parser[Target] =
    for {
      _ <- jumpOptionParser

      // Parse the actual  target
      targetName <- someSpacesParser >> stringParser
        if targetName == "MASQUERADE"

      // Parse the optional '--to-ports' target option
      // ([--to-ports port[-port]]).
      lowerPort <- optional(someSpacesParser >> parseString("--to-ports") >>
                            someSpacesParser >> portParser)

      // Try to parse the upper bound port only if the previous one succeeded.
      upperPort <-
        if (lowerPort.isDefined)
          optional(parseChar('-') >> portParser)
        else
          pure(None)
    } yield MasqueradeTarget(lowerPort, upperPort)
}

object MasqueradeTargetExtension extends TargetExtension {
  val targetParser = MasqueradeTarget.parser
}
