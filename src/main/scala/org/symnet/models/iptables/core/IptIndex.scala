// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet
package models.iptables
package core

final class IPTIndex(iptables: List[Table]) {

  ///
  /// Miscellanea
  ///

  val tableToUserChains: Map[Table, List[UserChain]] =
    iptables.map(table => table ->
      table.chains.collect { case chain: UserChain => chain }).toMap

  val tableToBuiltinChains: Map[Table, List[BuiltinChain]] =
    iptables.map(table => table ->
      table.chains.collect { case chain: BuiltinChain => chain }).toMap

  val allChains: List[Chain] = iptables.flatMap(_.chains)


  ///
  /// Quick access to relations between chains given by jumps.
  ///

  type AdjacencyLists = Map[Chain, Set[Chain]]

  val outAdjacencyLists: AdjacencyLists = allChains.map(chain => chain ->
    chain.rules.flatMap(_.target match {
      case uc: UserChain => Some(uc: Chain)
      case _             => None
    }).toSet).toMap

  val inAdjacencyLists:  AdjacencyLists = allChains.map(chain => chain ->
    outAdjacencyLists.flatMap { case (c, neighs) =>
      if (neighs.contains(chain)) Some(c) else None }.toSet).toMap

  ///
  /// Split a chain's rules between the rules which, if matches, jump to another
  /// chain.

  /** A rule is a 'boundary rule' if it jumps to a user defined chain. */
  def isBoundaryRule(rule: Rule): Boolean = rule.target match {
      case uc: UserChain => true
      case _             => false
  }

  val chainsSplitSubrules: Map[Chain, List[List[Rule]]] = allChains.map(chain =>
    chain -> {
      val rules = chain.rules

      if (rules.isEmpty) {
        Nil
      } else {
        // Get a list of indices of the rules which might jump to user-defined
        // chains.
        val indices =
          (-1) +:
          rules.init.zipWithIndex.filter(e => isBoundaryRule(e._1)).map(_._2) :+
          (rules.length - 1)

        // Use the list of indices to split the original list or rules into
        // (possibly) multiple sublists of rules, keeping the original ordering.
        (indices zip indices.tail) map {
          case (a, b) => rules.slice(a + 1, b + 1)
        }
      }
    }).toMap
}
