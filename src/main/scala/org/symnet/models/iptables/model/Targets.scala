// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet.models.iptables

// A target is the chain to which the control flow is passed after a rule
// matches (the '-j' parameter to the 'iptables' Linux administration tool).
package object model {
  type Target = Chain
}

package model {
  import Policy._

  // We distinguish two kinds of targets:
  //    * special targets
  //    * extension targets -- defined by iptables extensions.
  case class SpecialTarget(policy: Policy) extends Target(Nil, Some(policy))
  case class ExtensionTarget(
    rules: List[Rule],
    policy: Option[Policy]) extends Target(rules, policy)

  // The 'special targets' available in iptables.
  object AcceptTarget extends SpecialTarget(Policy.Accept)
  object DropTarget extends SpecialTarget(Policy.Drop)
  object ReturnTarget extends SpecialTarget(Policy.Return)
}
