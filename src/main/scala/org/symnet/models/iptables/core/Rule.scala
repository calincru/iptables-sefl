// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet.models.iptables
package core

class Rule(val matches: List[Match], val target: Target) {
  import filter.FilteringExtension.Impl.ProtocolMatch

  def matchesTcpOrUdp: Boolean =
    matches.exists(_ match {
      case ProtocolMatch(p) => p == "tcp" || p == "udp"
      case _ => false
    })

  def isValid(chain: Chain, table: Table): Boolean =
    // A rule is valid if all its matches are valid ...
    matches.forall(_.isValid(this, chain, table)) &&
    // ... and its target is valid.
    //
    // A target is valid if exactly one of the following is true:
    //  * it's a PlaceholderTarget and it `points' to a valid chain.
    //  * it's a regular target and its validity routine returns true.
    (target match {
      case PlaceholderTarget(name, _) => table.chains.exists(_.name == name)
      case _ => target.isValid(this, chain, table)
    })
}

object Rule {
  def apply(matches: List[Match], target: Target): Rule =
    new Rule(matches, target)
}
