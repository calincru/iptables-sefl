// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet.types

// Network related types.
object Net {
  class Ipv4(val host: String, val mask: Option[String])
}
