// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet.models.iptables
package core

class Rule(val matches: List[Match], val target: Target) {
  import filter.FilteringExtension.Impl.ProtocolMatch

  def matchesTcpOrUdp: Boolean =
    matches.exists(x => x match {
      case ProtocolMatch(p, true) => p == "tcp" || p == "udp"
      case _ => false
    })
}

object Rule {
  def apply(matches: List[Match], target: Target): Rule =
    new Rule(matches, target)
}
