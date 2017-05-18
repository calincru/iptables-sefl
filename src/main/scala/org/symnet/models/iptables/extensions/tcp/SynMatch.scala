// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet
package models.iptables
package extensions.tcp

// project
import core.{BaseParsers, Match}

object SynMatch extends BaseParsers {
  import ParserMP.monadPlusSyntax._

  def parser: Parser[Match] =
    for {
      _ <- spacesParser
      n1 <- optional(parseChar('!') >> someSpacesParser)
      _ <- parseString("--syn")
    } yield Match.maybeNegated(TcpFlagsMatch(Set("SYN", "RST", "ACK", "FIN"),
                                             Set("SYN")),
                               n1)
}
