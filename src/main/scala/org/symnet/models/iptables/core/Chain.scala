// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet.models.iptables.core

import Policy._

abstract class Chain(name: String, rules: List[Rule], policy: Option[Policy])

/** A user-defined chain cannot have an implicit policy in iptables. */
case class UserChain(
    name: String,
    rules: List[Rule]) extends Chain(name, rules, None)

/** iptables built-in chains *must* have a default policy. */
case class BuiltinChain(
    name: String,
    rules: List[Rule],
    policy: Policy) extends Chain(name, rules, Some(policy))

object Chain {
  def apply(name: String, rules: List[Rule], policy: Option[Policy]): Chain =
    policy match {
      case Some(p) => new BuiltinChain(name, rules, p)
      case None    => new UserChain(name, rules)
    }
}
