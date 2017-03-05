// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet.models.iptables

package object core {
  type Target = Chain

  object Target {
    case object placeholder extends Target("placeholder", Nil, None)
  }
}
