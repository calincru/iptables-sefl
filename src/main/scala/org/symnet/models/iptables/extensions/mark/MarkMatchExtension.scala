// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet
package models.iptables
package extensions.mark

// project
import core._

object MarkModuleLoader extends ModuleLoader {
  override def loaderParser: Parser[Match] =
    iptParsers.moduleLoaderParser("mark", new ModuleLoaderMatch {
      type Self = this.type
      override def extensionsEnabled = List(MarkMatchExtension)
    })
}

object MarkMatchExtension extends MatchExtension {
  override val matchParsers: List[Parser[Match]] = List(MarkMatch.parser)
}

case class MarkMatch(value: Long, mask: Option[Long]) extends Match {
  type Self = MarkMatch

  // TODO: Implement this.
  override def seflCondition(options: SeflGenOptions): SeflCondition = {
    SeflCondition.empty
  }
}

object MarkMatch extends BaseParsers {
  import ParserMP.monadPlusSyntax._

  def parser: Parser[Match] =
    for {
      _ <- spacesParser
      n1 <- optional(parseChar('!') >> someSpacesParser)
      _ <- parseString("--mark")

      // TODO: Change this to a general number (u32) parser.
      value <- hexLongParser
      maybeMask <- optional(parseChar('/') >> hexLongParser)
    } yield Match.maybeNegated(MarkMatch(value, maybeMask), n1)
}
