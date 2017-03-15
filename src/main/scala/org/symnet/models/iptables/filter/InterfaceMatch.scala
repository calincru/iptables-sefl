// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet
package models.iptables
package filter

import core._


case class InInterfaceMatch(val interface: String) extends Match {

  override protected def validateIf(
      rule: Rule,
      chain: Chain,
      table: Table): Boolean =
    chain match {
      case BuiltinChain(n, _, _) =>
        List("INPUT", "FORWARD", "PREROUTING") contains n
      case _ => false
    }
}

case class OutInterfaceMatch(val interface: String) extends Match {

  override protected def validateIf(
      rule: Rule,
      chain: Chain,
      table: Table): Boolean =
    chain match {
      case BuiltinChain(n, _, _) =>
        List("FORWARD", "OUTPUT", "POSTROUTING") contains n
      case _ => false
    }
}

object InterfaceMatch {
  import Parsing._
  import Combinators._
  import Parsing.ParserMP.monadPlusSyntax._

  def inParser: Parser[Match] =
    for {
      _   <- spacesParser >> oneOf(parseString("-i"),
                                   parseString("--in-interface"))
      neg <- optional(someSpacesParser >> parseChar('!'))
      int <- someSpacesParser >> stringParser
    } yield Match.maybeNegated(InInterfaceMatch(int), neg)

  def outParser: Parser[Match] =
    for {
      _   <- spacesParser >> oneOf(parseString("-o"),
                                   parseString("--out-interface"))
      neg <- optional(someSpacesParser >> parseChar('!'))
      int <- someSpacesParser >> stringParser
    } yield Match.maybeNegated(OutInterfaceMatch(int), neg)
}
