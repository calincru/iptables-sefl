// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet.models.iptables
package core

import scalaz.Maybe
import scalaz.Maybe.maybeInstance.traverse

case class Table(val name: String, val chains: List[Chain]) extends IptElement {
  type Self = Table

  ///
  /// Validation
  ///

  /** Checks the post-parsing (semantic) validity of this table. */
  override def validate(context: ValidationContext): Maybe[Table] =
    // A table is valid iff it is one of the currently supported ones ...
    if (List("filter", "nat", "mangle", "raw") contains name)
      // ... and all its chains are valid
      for {
        vChains <- traverse(chains)(
          _.validate(context.setTable(this)).asInstanceOf[Maybe[Chain]])
      } yield Table(name, vChains)
    else
      Maybe.empty
}
