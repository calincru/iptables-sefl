// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet.models.iptables.core

class Table(val name: String, val chains: List[Chain])

object Table {
  def apply(name: String, chains: List[Chain]): Table = new Table(name, chains)
}
