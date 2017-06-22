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
    addMatchExtensions(List(me))

  def addTargetExtension(te: TargetExtension): ParsingContext =
    addTargetExtensions(List(te))

  /** This function simply calls the one from above, as a module loader is a
   *  trait which extends `MatchExtension'. However, it is convenient when we
   *  want to be explicit about it.
   */
  def addModuleLoader(ml: ModuleLoader): ParsingContext = addMatchExtension(ml)

  def addMatchExtensions(mes: List[MatchExtension]): ParsingContext =
    ParsingContext(matchExtensions ++ mes, targetExtensions)

  def addTargetExtensions(tes: List[TargetExtension]): ParsingContext =
    ParsingContext(matchExtensions, targetExtensions ++ tes)
}

object ParsingContext {
  import extensions.filter.FilteringExtension
  import extensions.nat._
  import extensions.comment.CommentModuleLoader
  import extensions.tcp.TcpModuleLoader
  import extensions.udp.UdpModuleLoader
  import extensions.mark.{MarkModuleLoader, MarkTargetExtension}
  import extensions.connmark.{ConnmarkModuleLoader, ConnmarkTargetExtension}
  import extensions.conntrack.ConntrackModuleLoader

  def default: ParsingContext = ParsingContext(
    // Match extensions.
    List(
      // Filtering is included by default.
      FilteringExtension,

      // NOTE: We also include all matchers for module loaders.
      CommentModuleLoader,
      TcpModuleLoader,
      UdpModuleLoader,
      MarkModuleLoader,
      ConnmarkModuleLoader,
      ConntrackModuleLoader
    ),

    // Target extensions.
    List(
      // filter-related
      FilteringExtension,

      // NAT-related
      SnatTargetExtension,
      DnatTargetExtension,
      MasqueradeTargetExtension,
      RedirectTargetExtension,

      // mangle-related
      MarkTargetExtension,
      ConnmarkTargetExtension,

      // NOTE: Keep this one the last.
      ChainTargetExtension
    )
  )
}
