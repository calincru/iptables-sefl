// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet
package models.iptables
package core

/** A trait for classes implementing matcher parsers. */
trait MatchExtension extends BaseParsers {
  val matchParsers: List[Parser[Match]]
}

/** A trait for classes implementing target parsers. */
trait TargetExtension extends BaseParsers {
  val targetParser: Parser[Target]
}

/** A trait for classes implementing the parser which enables other match
 *  extensions.
 */
trait ModuleLoader extends MatchExtension {
  final override val matchParsers: List[Parser[Match]] = List(loaderParser)

  val loaderParser: Parser[Match]
}

object ChainTargetExtension extends TargetExtension {
  override val targetParser = iptParsers.chainTargetParser
}
