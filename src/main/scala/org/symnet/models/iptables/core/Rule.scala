// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet.models.iptables
package core

import scalaz.Maybe
import scalaz.Maybe._

class Rule(val matches: List[Match], val target: Target) {
  import filter.ProtocolMatch

  def matchesTcpOrUdp: Boolean =
    matches.exists(_ match {
      case ProtocolMatch(p) => p == "tcp" || p == "udp"
      case _ => false
    })

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

      // ... and its target is valid: if exactly one of the following is true:
      //  * it's a PlaceholderTarget and it `points' to a valid chain.
      //  * it's a regular target and its validity routine returns true.
      vTarget  <- target match {
        case PlaceholderTarget(name, _) =>
          Maybe.fromOption(table.chains.find(_.name == name))
        case _ => target.validate(this, chain, table)
      }
    } yield Rule(vMatches, vTarget)
}

object Rule {
  def apply(matches: List[Match], target: Target): Rule =
    new Rule(matches, target)
}
