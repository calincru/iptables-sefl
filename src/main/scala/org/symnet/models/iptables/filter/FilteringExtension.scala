// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet
package models.iptables
package filter

import core.{MatchExtension, TargetExtension}


object FilteringExtension extends MatchExtension with TargetExtension {
  val matchParsers  = List(
    ProtocolMatch.parser,
    IpMatch.srcParser, IpMatch.dstParser,
    InterfaceMatch.inParser, InterfaceMatch.outParser
  )
  val targetParser = FilterTarget.parser
}
