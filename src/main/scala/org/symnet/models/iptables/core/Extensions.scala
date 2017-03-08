// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet
package models.iptables
package core

/** A trait for classes implementing matcher parsers. */
trait MatchExtension {
  val matchParsers: List[Parsing.Parser[Match]]
}

/** A trait for classes implementing target parsers. */
trait TargetExtension {
  val targetParser: Parsing.Parser[Target]
}

object ChainTargetExtension extends TargetExtension {
  val targetParser = Parsing.chainTargetParser
}
