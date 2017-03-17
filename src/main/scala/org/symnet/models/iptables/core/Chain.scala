// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet.models.iptables
package core

import scalaz.Maybe
import scalaz.Maybe.empty

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

  ///
  /// Validation
  ///

  import scalaz.Maybe.maybeInstance.traverse

  protected def validateIf(table: Table): Boolean =
    // An abstract chain is valid if its name is unique across all chains in
    // this table ...
    table.chains.count(_.name == name) == 1

  def validate(table: Table): Maybe[Chain] =
    if (validateIf(table))
      // ... and all its rules are valid.
      for {
        vRules <- traverse(rules)(_.validate(this, table))
      } yield Chain(name, vRules, policy)
    else
      empty
}

/** A user-defined chain cannot have an implicit policy in iptables. */
case class UserChain(
    override val name: String,
    override val rules: List[Rule]) extends Chain(name, rules, None) {

  ///
  /// Validation
  ///
  /** Target validation routine: a user-defined chain is a valid target for a
   *  rule if and only if that rule is not part of the same chain (recursive
   *  jump).
   */
  override protected def validateIf(
      rule: Rule,
      chain: Chain,
      table: Table): Boolean = chain != this

  override protected def validateIf(table: Table): Boolean =
    // A built-in chain is valid if its parent class is valid ...
    super.validateIf(table) &&
    // ... and its name is not one of the reserved ones.
    !(List("PREROUTING",
           "FORWARD",
           "INPUT",
           "OUTPUT",
           "POSTROUTING") contains name)
}

/** iptables built-in chains must have a default policy. */
case class BuiltinChain(
    override val name: String,
    override val rules: List[Rule],
    val policy: Policy) extends Chain(name, rules, Some(policy)) {

  ///
  /// Validation
  ///

  /** Target validation routine: a builtin-chain is not a valid target.
   *
   *  NOTE: This could be acheived in a different manner, by making 'Target' a
   *  trait and making UserChain implement that trait, but it is currently
   *  easier to check validity in this way.
   */
  override protected def validateIf(
      rule: Rule,
      chain: Chain,
      table: Table): Boolean = false

  override protected def validateIf(table: Table): Boolean =
    // A built-in chain is valid if its parent class is valid ...
    super.validateIf(table) &&
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
