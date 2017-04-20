// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet
package models.iptables
package extensions

package object nat {
  // Tag names used to keep per flow state used to do NAT.
  val OriginalIP = "original-ip"
  val OriginalPort = "original-port"
  val NewIP = "new-ip"
  val NewPort = "new-port"
}
