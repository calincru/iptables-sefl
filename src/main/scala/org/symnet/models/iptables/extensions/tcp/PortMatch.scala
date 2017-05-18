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
import org.change.v2.analysis.processingmodels.instructions.{:&:, :>=:, :<=:, Constrain}
import org.change.v2.util.canonicalnames.{Proto, TcpSrc, TcpDst, TCPProto}

// project
import core._
import types.net.{Ipv4, Port}

case class SourcePortMatch(
    lowerPort: Port,
    upperPort: Option[Port]) extends Match {
  type Self = this.type

  override def seflCondition(options: SeflGenOptions): SeflCondition = {
    val (lower, upper) = (lowerPort, upperPort getOrElse lowerPort)

    SeflCondition.single(Constrain(TcpSrc, :&:(:>=:(ConstantValue(lower)),
                                               :<=:(ConstantValue(upper)))))
  }
}

case class DestinationPortMatch(
    lowerPort: Port,
    upperPort: Option[Port]) extends Match {
  type Self = this.type

  override def seflCondition(options: SeflGenOptions): SeflCondition = {
    val (lower, upper) = (lowerPort, upperPort getOrElse lowerPort)

    SeflCondition.single(Constrain(TcpDst, :&:(:>=:(ConstantValue(lower)),
                                               :<=:(ConstantValue(upper)))))
  }
}

object SourcePortMatch extends BaseParsers {
  import ParserMP.monadPlusSyntax._

  def parser: Parser[Match] =
    for {
      _  <- spacesParser
      n1 <- optional(parseChar('!') >> someSpacesParser)
      _  <- oneOf(parseString("--source-port"), parseString("--sport"))
      n2 <- conditional(optional(someSpacesParser >> parseChar('!')),
                        !n1.isDefined)
      lowerPort <- someSpacesParser >> portParser
      maybeUpperPort <- optional(parseChar(':') >> portParser)
    } yield Match.maybeNegated(
      SourcePortMatch(lowerPort, maybeUpperPort), n1 orElse n2.flatten)
}

object DestinationPortMatch extends BaseParsers {
  import ParserMP.monadPlusSyntax._

  def parser: Parser[Match] =
    for {
      _  <- spacesParser
      n1 <- optional(parseChar('!') >> someSpacesParser)
      _  <- oneOf(parseString("--destination-port"), parseString("--dport"))
      n2 <- conditional(optional(someSpacesParser >> parseChar('!')),
                        !n1.isDefined)
      lowerPort <- someSpacesParser >> portParser
      maybeUpperPort <- optional(parseChar(':') >> portParser)
    } yield Match.maybeNegated(
      DestinationPortMatch(lowerPort, maybeUpperPort), n1 orElse n2.flatten)
}
