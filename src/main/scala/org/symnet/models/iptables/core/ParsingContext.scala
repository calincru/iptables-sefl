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
 *    {{{
 *    implicit val context = ParsingContext(
 *      List(...),
 *      List(...)
 *    )
 *    }}}
 *
 *  or
 *
 *    {{{
 *    implicit val context = ParsingContext.default
 *    }}}
 *
 *  If support for jump's/goto's to user defined chains, the predefined
 *  ChainTargetExtension should be added last in the target extensions list.
 */
case class ParsingContext(
    matchExtensions:  List[MatchExtension],
    targetExtensions: List[TargetExtension]) {

  def addMatchExtension(me: MatchExtension): ParsingContext =
    ParsingContext(matchExtensions :+ me, targetExtensions)

  /** This function simply calls the one from above, as a module loader is a
   *  trait which extends `MatchExtension'. However, it is convenient when we
   *  want to be explicit about our intention.
   */
  def addModuleLoader(ml: ModuleLoader): ParsingContext = addMatchExtension(ml)

  def targetExtensions(te: TargetExtension): ParsingContext =
    ParsingContext(matchExtensions, targetExtensions :+ te)
}

object ParsingContext {
  import extensions.filter.{FilteringExtension}
  import extensions.nat._

  def default: ParsingContext = ParsingContext(
    // Match extensions.
    List(FilteringExtension),

    // Target extensions.
    List(
      FilteringExtension,
      SnatTargetExtension,
      DnatTargetExtension,
      MasqueradeTargetExtension,

      // NOTE: Keep this one the last.
      ChainTargetExtension
    )
  )
}
