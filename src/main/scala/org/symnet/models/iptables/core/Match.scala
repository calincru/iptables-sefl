// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet.models.iptables.core

import scalaz.Maybe
import scalaz.Maybe._

abstract class Match {

  ///
  /// Validation
  ///

  protected def validateIf(rule: Rule, chain: Chain, table: Table): Boolean =
    true

  def validate(rule: Rule, chain: Chain, table: Table): Maybe[Match] =
    if (validateIf(rule, chain, table))
      Just(this)
    else
      empty
}

case class NegatedMatch(m: Match) extends Match {
  override def validate(rule: Rule, chain: Chain, table: Table): Maybe[Match] =
    m.validate(rule, chain, table)
}

object Match {
  def maybeNegated[A](m: Match, o: Option[A]): Match =
    if (o.isDefined) NegatedMatch(m) else m
}
