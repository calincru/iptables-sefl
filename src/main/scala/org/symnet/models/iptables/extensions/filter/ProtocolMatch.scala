// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet
package models.iptables
package extensions.filter

import org.change.v2.analysis.processingmodels.Instruction

import core._

case class ProtocolMatch(val protocol: String) extends Match {

  override protected def validateIf(
      rule: Rule,
      chain: Chain,
      table: Table): Boolean =
    // Check if it is one of the 'named' protocols
    (List("tcp", "udp", "icmp", "all") contains protocol) ||
    // TODO(calincru): Check if it is a valid numeric protocol or a protocol
    // from /etc/protocols.
    false

  // TODO
  def seflConstrain(options: SeflGenOptions): Instruction = null
}

object ProtocolMatch extends BaseParsers {

  def ruleMatchesTcpOrUdp(rule: Rule): Boolean =
    rule.matches.exists(_ match {
      case ProtocolMatch(p) => p == "tcp" || p == "udp"
      case _ => false
    })

  import ParserMP.monadPlusSyntax._

  def parser: Parser[Match] =
    for {
      _        <- spacesParser >> oneOf(parseString("-p"),
                                        parseString("--protocol"))
      neg      <- optional(someSpacesParser >> parseChar('!'))
      protocol <- someSpacesParser >> stringParser
  } yield Match.maybeNegated(ProtocolMatch(protocol), neg)
}
