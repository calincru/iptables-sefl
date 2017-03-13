// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet.models.iptables.core

abstract class Match {
  def isValid(rule: Rule, chain: Chain, table: Table): Boolean
}

case class NegatedMatch(m: Match) extends Match {
  def isValid(rule: Rule, chain: Chain, table: Table): Boolean =
    m.isValid(rule, chain, table)
}

object Match {
  def maybeNegated[A](m: Match, o: Option[A]): Match =
    if (o.isDefined) NegatedMatch(m) else m
}
