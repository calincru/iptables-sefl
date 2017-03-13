// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet.models.iptables.core

object Policy extends Enumeration {
  type Policy = Value
  val Accept, Drop, Return = Value

  // TODO(calincru): There is also a QUEUE policy; is it relevant?
  def apply(s: String): Option[Policy] =
    s match {
      case "ACCEPT" => Some(Accept)
      case "DROP"   => Some(Drop)
      case "RETURN" => Some(Return)
      case _        => None
    }
}
import Policy._

sealed abstract class Chain(
    val name: String,
    val rules: List[Rule],
    policy: Option[Policy]) extends Target(name) {

  def isValid(table: Table): Boolean =
    // An abstract chain is valid if its name is unique across all chains in
    // this table ...
    table.chains.count(_.name == name) == 1 &&
    // ... and all its rules are valid.
    rules.forall(_.isValid(this, table))

  /** The validation routine, inherrited from class 'Target'.
   *
   *  A chain can be the target of any rule.
   */
  override def isValid(rule: Rule, chain: Chain, table: Table): Boolean = true
}

/** A user-defined chain cannot have an implicit policy in iptables. */
case class UserChain(
    override val name: String,
    override val rules: List[Rule]) extends Chain(name, rules, None) {

  /** A user-defined chain can be part of any table. */
  override def isValid(table: Table): Boolean = super.isValid(table)
}

/** iptables built-in chains must have a default policy. */
case class BuiltinChain(
    override val name: String,
    override val rules: List[Rule],
    val policy: Policy) extends Chain(name, rules, Some(policy)) {

  override def isValid(table: Table): Boolean =
    // A built-in chain is valid if its parent class is valid ...
    super.isValid(table) &&
    // ... and it conforms to the chain/table restrictions.
    ((name match {
      case "PREROUTING"  => List("nat", "mangle")
      case "FORWARD"     => List("mangle", "filter")
      case "INPUT"       => List("mangle", "filter")
      case "OUTPUT"      => List("nat", "mangle", "filter")
      case "POSTROUTING" => List("nat", "mangle")
      case _             => Nil
    }) contains table.name)
}

object Chain {
  def apply(name: String, rules: List[Rule], policy: Option[Policy]): Chain =
    policy match {
      case Some(p) => new BuiltinChain(name, rules, p)
      case None    => new UserChain(name, rules)
    }
}
