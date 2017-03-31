// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet
package models.iptables
package extensions.filter

import core._
import types.net.Ipv4

case class SourceMatch(val ip: Ipv4) extends Match

case class DestinationMatch(val ip: Ipv4) extends Match

object IpMatch extends BaseParsers {
  import ParserMP.monadPlusSyntax._

  def srcParser: Parser[Match] =
    for {
      _   <- spacesParser >> oneOf(parseString("-s"),
                                   parseString("--source"),
                                   parseString("--src"))
      neg <- optional(someSpacesParser >> parseChar('!'))
      ip  <- someSpacesParser >> ipParser
    } yield Match.maybeNegated(SourceMatch(ip), neg)

  def dstParser: Parser[Match] =
    for {
      _   <- spacesParser >> oneOf(parseString("-d"),
                                   parseString("--destination"),
                                   parseString("--dst"))
      neg <- optional(someSpacesParser >> parseChar('!'))
      ip  <- someSpacesParser >> ipParser
    } yield Match.maybeNegated(DestinationMatch(ip), neg)
}
