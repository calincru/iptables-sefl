// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet.models.iptables.core

object Policy extends Enumeration {
  type Policy = Value
  val Accept, Drop, Return = Value

  // TODO(calincru): There is also a QUEUE policy; is it relevant?
  def apply(s: String): Option[Policy] =
    s match {
      case "ACCEPT" => Some(Accept)
      case "DROP"   => Some(Drop)
      case "RETURN" => Some(Return)
      case _        => None
    }
}
