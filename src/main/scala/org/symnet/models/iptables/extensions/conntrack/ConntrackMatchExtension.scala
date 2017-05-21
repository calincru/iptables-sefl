// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet
package models.iptables
package extensions.conntrack

// project
import core._

object ConntrackModuleLoader extends ModuleLoader {
  override def loaderParser: Parser[Match] =
    iptParsers.moduleLoaderParser("conntrack", new ModuleLoaderMatch {
      type Self = this.type
      override def extensionsEnabled = List(ConntrackMatchExtension)
    })
}

object ConntrackMatchExtension extends MatchExtension {
  // TODO: There are other unsupported options.
  override val matchParsers: List[Parser[Match]] = List(
    CtstateMatch.parser,
    CtprotoMatch.parser
  )
}
