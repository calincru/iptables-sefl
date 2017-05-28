// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet
package models.iptables
package extensions.conntrack

// project
import core._
import extensions.filter.ProtocolMatch

object CtprotoMatch extends BaseParsers {
  import ParserMP.monadPlusSyntax._

  def parser: Parser[Match] =
    for {
      _ <- spacesParser
      n1 <- optional(parseChar('!') >> someSpacesParser)
      _ <- parseString("--ctproto")
      n2 <- conditional(optional(someSpacesParser >> parseChar('!')),
                        !n1.isDefined)
      l4proto <- someSpacesParser >> identifierParser

    // TODO: Is it OK to reuse the ProtocolMatch match?  It matches the `Proto'
    // field in the L4 header.
    } yield Match.maybeNegated(ProtocolMatch(l4proto), n1 orElse n2.flatten)
}
