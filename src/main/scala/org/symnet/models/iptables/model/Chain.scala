// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet.models.iptables.model

import Policy._

class Chain(rules: List[Rule], policy: Option[Policy])

// A user-defined chain cannot have an implicit policy in iptables.
case class UserChain(rules: List[Rule]) extends Chain(rules, None)

// iptables built-in chains *must* have a default policy.
case class BuiltinChain(
  rules: List[Rule],
  policy: Policy) extends Chain(rules, Some(policy))
