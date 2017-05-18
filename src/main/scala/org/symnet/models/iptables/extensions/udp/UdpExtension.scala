// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet
package models.iptables
package extensions.udp

// 3rd-party
// -> Symnet
import org.change.v2.analysis.processingmodels.Instruction

// project
import core._
import extensions.tcp.{DestinationPortMatch, SourcePortMatch}

object UdpModuleLoader extends ModuleLoader {
  override def loaderParser: Parser[Match] =
    iptParsers.moduleLoaderParser("udp", new ModuleLoaderMatch {
      type Self = this.type
      override def extensionsEnabled = List(UdpExtension)
    })
}

object UdpExtension extends MatchExtension {
  // NOTE: It reuses the parsers defined as part of the TCP extension.
  override val matchParsers: List[Parser[Match]] = List(
    SourcePortMatch.parser,
    DestinationPortMatch.parser
  )
}
