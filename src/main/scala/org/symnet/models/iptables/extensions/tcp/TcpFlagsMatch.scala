// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet
package models.iptables
package extensions.tcp

// 3rd-party
// -> Symnet
import org.change.v2.analysis.expression.concrete.ConstantValue
import org.change.v2.analysis.processingmodels.Instruction
import org.change.v2.analysis.processingmodels.instructions.{:&:, :==:, Constrain}
import org.change.v2.util.canonicalnames._

// project
import core._
import types.net.{Ipv4, Port}

case class TcpFlagsMatch(
    toCheck: Set[String],
    toBeSet: Set[String]) extends Match {

  private val allFlags = Set("SYN", "ACK", "FIN", "RST", "URG", "PSH")
  private val flagsToOffset = Map(
    "SYN" -> TcpFlagSYN,
    "ACK" -> TcpFlagACK,
    "FIN" -> TcpFlagFIN,
    "RST" -> TcpFlagRST,
    "URG" -> TcpFlagURG,
    "PSH" -> TcpFlagPSH
  )

  override protected def validateIf(context: ValidationContext): Boolean =
    // NONE cannot appear in the left hand side.
    toCheck.subsetOf(allFlags + "ALL") &&
    // `toBeSet' should be included in `toCheck'
    //    OR `toCheck' should include 'ALL'
    //    OR `toBeSet' is just Set(NONE) or Set(ALL
    (toBeSet.subsetOf(toCheck) ||
      toCheck.contains("ALL") ||
      toBeSet == Set("NONE") ||
      toBeSet == Set("ALL"))

  override def seflCondition(options: SeflGenOptions): SeflCondition = {
    val mask = if (toCheck.contains("ALL")) allFlags else toCheck
    val set  = if (toBeSet == Set("NONE")) Set.empty[String]
               else if (toBeSet == Set("ALL")) mask else toBeSet
    val unset = mask &~ set

    SeflCondition.conjunction(
      set.map(f => Constrain(flagsToOffset(f), :==:(ConstantValue(1)))).toList ++
      unset.map(f => Constrain(flagsToOffset(f), :==:(ConstantValue(0))))
    )
  }
}

object TcpFlagsMatch extends BaseParsers {
  import ParserMP.monadPlusSyntax._

  def parser: Parser[Match] =
    for {
      _ <- spacesParser
      n1 <- optional(parseChar('!') >> someSpacesParser)
      _ <- parseString("--tcp-flags")
      n2 <- conditional(optional(someSpacesParser >> parseChar('!')),
                        !n1.isDefined)
      toCheckList <- someSpacesParser >> parseUntil(' ')
      toBeSetList <- someSpacesParser >> parseUntil(' ')
    } yield Match.maybeNegated(TcpFlagsMatch(toCheckList.split(',').toSet,
                                             toBeSetList.split(',').toSet),
                               n1 orElse n2.flatten)
}
