// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet.models.iptables
package extensions.comment

// 3rd-party
// -> Symnet
import org.change.v2.analysis.processingmodels.Instruction

// project
import core._

object CommentModuleLoader extends ModuleLoader {
  override def loaderParser: Parser[Match] =
    iptParsers.moduleLoaderParser("comment", new ModuleLoaderMatch {
      type Self = this.type
      override def extensionsEnabled = List(CommentExtension)
    })
}

object CommentExtension extends MatchExtension {
  override val matchParsers: List[Parser[Match]] = List(CommentMatch.parser)
}

case class CommentMatch(comment: String) extends Match {
  type Self = this.type

  override def seflCondition(options: SeflGenOptions): SeflCondition =
    SeflCondition.empty
}

object CommentMatch extends BaseParsers {
  import ParserMP.monadPlusSyntax._

  def parser: Parser[Match] =
    for {
      _ <- spacesParser
      _ <- parseString("--comment")
      comment <- someSpacesParser >> parseChar('"') >> parseUntil('"')
      _ <- parseChar('"')
    } yield CommentMatch(comment)
}
