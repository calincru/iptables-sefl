// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet.models.iptables
package core

// 3rd-party
// -> Symnet
import org.change.v2.analysis.processingmodels.Instruction
import org.change.v2.analysis.processingmodels.instructions.Forward

// -> scalaz
import scalaz.Maybe
import scalaz.Maybe.maybeInstance.traverse

// project
import virtdev.{Port => Interface}
import Policy._

sealed abstract class Chain(
    val name: String,
    val rules: List[Rule],
    policy: Option[Policy]) extends IptElement {
  type Self <: Chain

  /** Some rules could generate other rules to enable us to model them in SEFL
   *  (see @Rule#mutate for an example).
   */
  protected def mutatedRules(interfaces: List[Interface]): List[Rule] =
    rules.flatMap(_.mutate(interfaces))

  ///
  /// Validation
  ///

  override protected def validateIf(context: ValidationContext): Boolean = {
    val table = context.table.get

    // An abstract chain is valid if its name is unique across all chains in
    // this table ...
    table.chains.count(_.name == name) == 1
  }
}

/** A user-defined chain cannot have an implicit policy in iptables. */
case class UserChain(
    override val name: String,
    override val rules: List[Rule])
  extends Chain(name, rules, None) with Target {

  type Self = UserChain

  ///
  /// Validation
  ///

  override protected def validateIf(context: ValidationContext): Boolean =
    // A user-defined chain is valid if its parent class is valid ...
    super.validateIf(context) && (
    // dispatch on whether this is validated as a target or as a chain
    if (context.chain.isDefined) {
      val chain = context.chain.get
      val table = context.table.get

      chain != this && table.chains.contains(this)
    } else {
      // ... and its name is not one of the reserved ones.
      !(List("PREROUTING",
             "FORWARD",
             "INPUT",
             "OUTPUT",
             "POSTROUTING") contains name)
    })

  override def validate(context: ValidationContext): Maybe[UserChain] =
    if (validateIf(context))
      for {
        vRules <- traverse(mutatedRules(context.interfaces))(
          _.validate(context.setChain(this)))
      } yield UserChain(name, vRules)
    else
      Maybe.empty

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
  type Self = BuiltinChain

  ///
  /// Validation
  ///

  override protected def validateIf(context: ValidationContext): Boolean = {
    val table = context.table.get

    // A built-in chain is valid if its parent class is valid ...
    super.validateIf(context) &&
    // ... and it conforms to the chain/table restrictions.
    ((name match {
      case "PREROUTING"  => List("raw", "nat", "mangle")
      case "FORWARD"     => List("mangle", "filter")
      case "INPUT"       => List("nat", "mangle", "filter")
      case "OUTPUT"      => List("raw", "nat", "mangle", "filter")
      case "POSTROUTING" => List("nat", "mangle")
      case _             => Nil
    }) contains table.name)
  }

  override def validate(context: ValidationContext): Maybe[BuiltinChain] =
    if (validateIf(context))
      for {
        vRules <- traverse(mutatedRules(context.interfaces))(
          _.validate(context.setChain(this)))
      } yield BuiltinChain(name, vRules, policy)
    else
      Maybe.empty
}
