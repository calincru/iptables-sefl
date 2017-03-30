// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet
package models.iptables
package filter

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
}

object ProtocolMatch extends BaseParsers {
  import ParserMP.monadPlusSyntax._

  def parser: Parser[Match] =
    for {
      _        <- spacesParser >> oneOf(parseString("-p"),
                                        parseString("--protocol"))
      neg      <- optional(someSpacesParser >> parseChar('!'))
      protocol <- someSpacesParser >> stringParser
  } yield Match.maybeNegated(ProtocolMatch(protocol), neg)
}
