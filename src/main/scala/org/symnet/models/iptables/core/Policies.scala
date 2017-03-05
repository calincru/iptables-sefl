// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet.models.iptables.core

object Policy extends Enumeration {
  type Policy = Value
  val Accept, Drop, Return = Value

  def apply(s: String): Option[Policy] =
    s.toLowerCase match {
      case "accept" => Some(Accept)
      case "drop"   => Some(Drop)
      case "return" => Some(Return)
      case _        => None
    }
}
