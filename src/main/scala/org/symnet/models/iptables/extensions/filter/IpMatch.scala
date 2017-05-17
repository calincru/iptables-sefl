// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet
package models.iptables
package extensions.filter

import org.change.v2.analysis.expression.concrete.ConstantValue
import org.change.v2.analysis.processingmodels.Instruction
import org.change.v2.analysis.processingmodels.instructions.{:&:, :>=:, :<=:, Constrain}
import org.change.v2.util.canonicalnames.{IPDst, IPSrc}

import core._
import types.net.Ipv4

case class SourceMatch(ip: Ipv4) extends Match {
  type Self = SourceMatch

  override def seflConstrain(options: SeflGenOptions): Option[Instruction] = {
    val (lower, upper) = ip.toHostRange

    Some(Constrain(IPSrc, :&:(:>=:(ConstantValue(lower.host)),
                              :<=:(ConstantValue(upper.host)))))
  }
}

case class DestinationMatch(ip: Ipv4) extends Match {
  type Self = DestinationMatch

  override def seflConstrain(options: SeflGenOptions): Option[Instruction] = {
    val (lower, upper) = ip.toHostRange

    Some(Constrain(IPDst, :&:(:>=:(ConstantValue(lower.host)),
                              :<=:(ConstantValue(upper.host)))))
  }
}

// NOTE: Address specified by hostname is not supported; it cannot be modeled.
object IpMatch extends BaseParsers {
  import ParserMP.monadPlusSyntax._

  def srcParser: Parser[Match] =
    for {
      _  <- spacesParser
      n1 <- optional(parseChar('!') >> someSpacesParser)
      _  <- oneOf(parseString("-s"),
                  parseString("--source"),
                  parseString("--src"))
      n2 <- conditional(optional(someSpacesParser >> parseChar('!')),
                        !n1.isDefined)
      ip <- someSpacesParser >> ipParser
    } yield Match.maybeNegated(SourceMatch(ip), n1 orElse n2.flatten)

  def dstParser: Parser[Match] =
    for {
      _  <- spacesParser
      n1 <- optional(parseChar('!') >> someSpacesParser)
      _  <- oneOf(parseString("-d"),
                  parseString("--destination"),
                  parseString("--dst"))
      n2 <- conditional(optional(someSpacesParser >> parseChar('!')),
                        !n1.isDefined)
      ip <- someSpacesParser >> ipParser
    } yield Match.maybeNegated(DestinationMatch(ip), n1 orElse n2.flatten)
}
