// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet.models.iptables
package core

import org.change.v2.analysis.processingmodels.Instruction
import org.change.v2.analysis.processingmodels.instructions.Forward

import scalaz.Maybe

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
    policy: Option[Policy]) {

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
      Maybe.empty
}

/** A user-defined chain cannot have an implicit policy in iptables. */
case class UserChain(
    override val name: String,
    override val rules: List[Rule])
  extends Chain(name, rules, None) with Target {

  ///
  /// Validation
  ///

  override protected def validateIf(table: Table): Boolean =
    // A user-defined chain is valid if its parent class is valid ...
    super.validateIf(table) &&
    // ... and its name is not one of the reserved ones.
    !(List("PREROUTING",
           "FORWARD",
           "INPUT",
           "OUTPUT",
           "POSTROUTING") contains name)

  /** Target validation routine: a user-defined chain is a valid target for a
   *  rule if and only if that rule is not part of the same chain (recursive
   *  jump).
   */
  override protected def validateIf(
      rule: Rule,
      chain: Chain,
      table: Table): Boolean = chain != this && table.chains.contains(this)

  ///
  /// Sefl code generation (this chain is the target of a rule).
  ///

  // When a user chain is the target of a rule, we forward the packet to the
  // jump port of the corresponding Iptables Virtual Device (IVD).
  override def seflCode(options: SeflGenOptions): Instruction =
    Forward(options.jumpPort)
}

/** iptables built-in chains must have a default policy. */
case class BuiltinChain(
    override val name: String,
    override val rules: List[Rule],
    val policy: Policy) extends Chain(name, rules, Some(policy)) {

  ///
  /// Validation
  ///

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
