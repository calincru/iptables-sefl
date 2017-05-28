// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet
package models.iptables
package extensions.connmark

// 3rd-party
// -> Symnet
import org.change.v2.analysis.expression.concrete.ConstantBitVector
import org.change.v2.analysis.expression.concrete.nonprimitive.{:@, <|>, <&>}
import org.change.v2.analysis.processingmodels.instructions._

// project
import core._
import extensions.mark.MarkMatch

object ConnmarkModuleLoader extends ModuleLoader {
  override def loaderParser: Parser[Match] =
    iptParsers.moduleLoaderParser("connmark", new ModuleLoaderMatch {
      type Self = this.type
      override def extensionsEnabled = List(ConnmarkMatchExtension)
    })
}

object ConnmarkMatchExtension extends MatchExtension {
  override val matchParsers: List[Parser[Match]] = List(
    MarkMatch.parser((value, maybeMask) => ConnmarkMatch(value, maybeMask))
  )
}

case class ConnmarkMatch(value: Long, maybeMask: Option[Long]) extends Match {
  type Self = ConnmarkMatch

  override def seflCondition(options: SeflGenOptions): SeflCondition = {
    val ctmarkTag = virtdev.ctmarkTag(options.deviceId)
    val ctmarkTmpTag = ctmarkTag + "-tmp"
    val mask = maybeMask getOrElse 0xFFFFFFFFL

    SeflCondition.single(
      initInstr =
        Assign(ctmarkTmpTag, <&>(:@(ctmarkTag), ConstantBitVector(mask))),
      constraint = Constrain(ctmarkTmpTag, :==:(ConstantBitVector(value)))
    )
  }
}
