// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet
package models.iptables
package extensions.tcp

// 3rd-party
// -> Symnet
import org.change.v2.analysis.processingmodels.Instruction

// project
import core._

object TcpModuleLoader extends ModuleLoader {
  override def loaderParser: Parser[Match] =
    iptParsers.moduleLoaderParser("tcp", new ModuleLoaderMatch {
      type Self = this.type
      override def extensionsEnabled = List(TcpExtension)
    })
}

object TcpExtension extends MatchExtension {
  override val matchParsers: List[Parser[Match]] = List(
    SourcePortMatch.parser,
    DestinationPortMatch.parser,
    TcpFlagsMatch.parser,
    SynMatch.parser
  )
}
