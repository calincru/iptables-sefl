// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet.models.iptables.core

class Table(val name: String, val chains: List[Chain]) {

  /** Checks the post-parsing (semantic) validity of this table. */
  def isValid: Boolean =
    // A table is valid iff it is one of the currently supported ones.
    (List("filter", "nat", "mangle", "raw") contains name) &&
    // And all its chains are valid.
    chains.forall(_.isValid(this))
}

object Table {
  def apply(name: String, chains: List[Chain]): Table = new Table(name, chains)
}
