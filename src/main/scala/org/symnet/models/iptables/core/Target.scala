// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet.models.iptables.core

import org.change.v2.analysis.processingmodels.Instruction

import scalaz.Maybe
import scalaz.Maybe._

abstract class Target(name: String) {

  ///
  /// Validation
  ///

  protected def validateIf(rule: Rule, chain: Chain, table: Table): Boolean =
    true

  def validate(rule: Rule, chain: Chain, table: Table): Maybe[Target] =
    if (validateIf(rule, chain, table))
      Just(this)
    else
      empty

  ///
  /// Sefl code generation
  ///

  /** Generates the FORWARD and any other SEFL instructions that match this
   *  target's semantics.
   */
  def seflCode(options: SeflGenOptions): Instruction
}

/** PLaceholder target is used when a (possible) forward reference to a user
 *  defined chain is made.
 *
 *  The replacement in the resulting parse tree is done at a later stage
 *  (following the complete parsing).
 */
case class PlaceholderTarget(
    name: String,
    goto: Boolean = false) extends Target(name) {

  /** We shouldn't get to check the validty of a placeholder target. */
  override def validate(rule: Rule, chain: Chain, table: Table): Maybe[Target] =
    empty
  override def seflCode(options: SeflGenOptions): Instruction = null
}
