// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet
package models.iptables
package core

/** The parsing context.
 *
 *  Example usage before initiating the parsing.
 *
 *  {{{
 *  implicit val context = new ParsingContext {
 *    matchExtensions  = List(...)
 *    targetExtensions = List(...)
 *  }
 *  }}}
 *
 *  If support for jump's/goto's to user defined chains, the predefined
 *  ChainTargetExtension should be added last in the target extensions list.
 */
abstract class ParsingContext {
  val matchExtensions:  List[MatchExtension]
  val targetExtensions: List[TargetExtension]
}
