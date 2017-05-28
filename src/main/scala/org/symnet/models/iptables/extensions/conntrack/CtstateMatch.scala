// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet
package models.iptables
package extensions.conntrack

// 3rd-party
// -> Symnet
import org.change.v2.analysis.expression.concrete.ConstantValue
import org.change.v2.analysis.processingmodels.instructions.{:==:, Constrain}

// project
import core._

// NOTE: The state `Related' is added just for completeness, but we cannot model
// it in SEFL.
object ConnectionState extends Enumeration {

  // TODOs: What are the precise rules for a packet to be considered INVALID
  // (rather than NEW)?

  type ConnectionState = Value
  val Invalid, New, Established, Related, Untracked, Snat, Dnat = Value

  def apply(s: String): Option[ConnectionState] =
    s match {
      case "DNAT" => Some(Dnat)
      case "SNAT" => Some(Snat)
      case "NEW" => Some(New)
      case "ESTABLISHED" => Some(Established)
      case "UNTRACKED" => Some(Untracked)
      case _ => None
    }
}

case class CtstateMatch(strStates: List[String]) extends Match {
  private val states = strStates.flatMap(s => ConnectionState(s))

  override protected def validateIf(context: ValidationContext): Boolean =
    states.size == strStates.size

  override def seflCondition(options: SeflGenOptions): SeflCondition = {
    val ctstateTag = virtdev.ctstateTag(options.deviceId)
    val snatStateTag = virtdev.snatStateTag(options.deviceId)
    val dnatStateTag = virtdev.dnatStateTag(options.deviceId)

    SeflCondition.conjunction(
      states.map(_ match {
        // Handle virtual states separately (SNAT and DNAT).
        case ConnectionState.Snat =>
          Constrain(snatStateTag, :==:(ConstantValue(1)))
        case ConnectionState.Dnat =>
          Constrain(dnatStateTag, :==:(ConstantValue(1)))

        // NOTE: Make sure to default this to the valid value when a new packet
        // is inserted.
        case s @ _ =>
          Constrain(ctstateTag, :==:(ConstantValue(s.id)))
      })
    )
  }
}

object CtstateMatch extends BaseParsers {
  import ParserMP.monadPlusSyntax._

  def parser: Parser[Match] =
    for {
      _ <- spacesParser
      n1 <- optional(parseChar('!') >> someSpacesParser)
      _ <- parseString("--ctstate")
      n2 <- conditional(optional(someSpacesParser >> parseChar('!')),
                        !n1.isDefined)
      statelist <- someSpacesParser >> parseUntil(' ')
    } yield Match.maybeNegated(CtstateMatch(statelist.split(',').toList),
                               n1 orElse n2.flatten)
}
