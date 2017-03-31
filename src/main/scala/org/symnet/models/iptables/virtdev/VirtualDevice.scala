// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet
package models.iptables
package virtdev

abstract class VirtualDevice[+Config](
    val name:         String,
    val inputPorts:   Int,
    val outputPorts:  Int,
    val config:       Config) {

  def inputPort(which: Int): Port = s"$name-in"
  def outputPort(which: Int): Port = s"$name-out"
}
