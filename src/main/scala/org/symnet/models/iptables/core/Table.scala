// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet.models.iptables
package core

import scalaz.Maybe

case class Table(val name: String, val chains: List[Chain]) {

  ///
  /// Validation
  ///
  import scalaz.Maybe.maybeInstance.traverse

  /** Checks the post-parsing (semantic) validity of this table. */
  def validate: Maybe[Table] =
    // A table is valid iff it is one of the currently supported ones ...
    if (List("filter", "nat", "mangle", "raw") contains name)
      // ... and all its chains are valid
      for {
        vChains <- traverse(chains)(_.validate(this))
      } yield Table(name, vChains)
    else
      Maybe.empty
}
