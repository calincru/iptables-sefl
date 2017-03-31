// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet.models.iptables
package core

import scalaz.Maybe
import scalaz.Maybe._

case class Rule(val matches: List[Match], val target: Target) {

  ///
  /// Validation
  ///

  import scalaz.Maybe.maybeInstance.traverse

  /** The `traverse' combinator is the equivalent to `mapM' in Haskell.  It maps
   *  each element of a structure to a monadic action, evaluates these actions
   *  from left to right, and collects the results.
   *
   *  NOTE: The `v' in `v[Name]' stands for `validated'.
   */

  def validate(chain: Chain, table: Table): Maybe[Rule] =
    for {
      // A rule is valid if all its matches are valid ...
      vMatches <- traverse(matches)(_.validate(this, chain, table))

      // ... and its 'real' target is valid.
      //
      // NOTE: The 'real' target of a rule could be another one than that used
      // when constructing it only if it is a placeholder target which refers a
      // valid (from a 'target' perspective) chain.
      actualTarget  <- target match {
        case PlaceholderTarget(name, _) =>
          Maybe.fromOption(table.chains.find(_.name == name))
        case _ => Just(target)
      }
      vTarget <- actualTarget.validate(this, chain, table)
    } yield Rule(vMatches, vTarget)
}
