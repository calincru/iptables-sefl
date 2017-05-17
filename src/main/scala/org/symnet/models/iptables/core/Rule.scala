// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet.models.iptables
package core

// 3rd-party
// -> scalaz
import scalaz.Maybe
import scalaz.Maybe._
import scalaz.Maybe.maybeInstance.traverse

// project
import virtdev.{Port => Interface}

case class Rule(
    matches: List[Match],
    target: Target,
    goto: Boolean = false) extends IptElement {
  type Self = Rule

  /** One rule could generate a few others (see below for an example).
   *
   *  NOTE: This list should include this rule, if after 'mutation' it is still
   *  meaningful.  This method gets called right before validation.
   *
   *  Examples:
   *    -i qr-+ -j ACCEPT
   *    -o eth+ -j DROP
   */
  def mutate(interfaces: List[Interface]): List[Rule] = {
    import extensions.filter.{InInterfaceMatch, OutInterfaceMatch}

    val (regexMatches, nonregexMatches) = matches.partition(_ match {
      case InInterfaceMatch(_, true) | OutInterfaceMatch(_, true) => true
      case _ => false
    })

    if (regexMatches.isEmpty) {
      List(this)
    } else {
      val inInterfaces = regexMatches.collect {
        case inMatch @ InInterfaceMatch(name, true) =>
          interfaces.filter(_.startsWith(name))
      }
      val outInterfaces = regexMatches.collect {
        case outMatch @ OutInterfaceMatch(name, true) =>
          interfaces.filter(_.startsWith(name))
      }
      val inCombinations: List[List[Match]] = cartesianJoin(
        inInterfaces.map(_.map(in => InInterfaceMatch(in, false))))
      val outCombinations: List[List[Match]] = cartesianJoin(
        outInterfaces.map(_.map(out => OutInterfaceMatch(out, false))))
      val allCombinations: List[List[Match]] =
        inCombinations.map(ins => outCombinations.map(_ ++ ins)).flatten

      allCombinations.map(combs => Rule(nonregexMatches ++ combs, target))
    }
  }

  ///
  /// Validation
  ///

  /** The `traverse' combinator is the equivalent to `mapM' in Haskell.  It maps
   *  each element of a structure to a monadic action, evaluates these actions
   *  from left to right, and collects the results.
   *
   *  NOTE: The `v' in `v[Name]' stands for `validated'.
   */
  override def validate(context: ValidationContext): Maybe[Rule] = {
    val chain = context.chain.get
    val table = context.table.get

    for {
      // A rule is valid if all its matches are valid ...
      vMatches <- traverse(matches)(
        _.validate(context.setRule(this)).asInstanceOf[Maybe[Match]])

      // ... and its 'real' target is valid.
      //
      // NOTE: The 'real' target of a rule could be another one than that used
      // when constructing it only if it is a placeholder target which refers a
      // valid (from a 'target' perspective) chain.
      actualResult <- target match {
        case PlaceholderTarget(name, goto) => {
          // Find the user-defined chains that match this placeholder's name.
          val matchedChains = table.chains.collect {
            case uc @ UserChain(chainName, _) if chainName == name => uc
          }

          // If more than 1 or 0 have been found, it is an error.
          if (matchedChains.length == 1)
            Just((matchedChains.head, goto))
          else
            empty
        }
        case _ => Just((target, false))
      }
      vTarget <- actualResult._1.validate(context.setRule(this))
    } yield Rule(vMatches, vTarget, actualResult._2)
  }
}
