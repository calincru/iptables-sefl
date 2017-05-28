// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet
package models.iptables
package extensions.ct

// 3rd-party
// -> Symnet
import org.change.v2.analysis.expression.concrete.ConstantValue
import org.change.v2.analysis.processingmodels.Instruction
import org.change.v2.analysis.processingmodels.instructions._

// -> scalaz
import scalaz.Maybe

// project
import core._
import extensions.conntrack.ConnectionState

// The CT target allows to set parameters for a packet or its associated
// connection. The target attaches a "template" connection tracking entry to the
// packet, which is then used by the conntrack core when initializing a new ct
// entry. This target is thus only valid in the "raw" table.
case class CtTarget(option: CtTarget.Option) extends Target {
  type Self = option.Self

  override protected def validateIf(context: ValidationContext): Boolean =
    // ... this target is thus only valid in the "raw" table.
    context.table.get.name == "raw"

  override def validate(context: ValidationContext): Maybe[Self] =
    for {
      // NOTE: We do this here to ensure that `validateIf' is called.
      _ <- super.validate(context)
      vOption <- option.validate(context)
    } yield vOption

  override def seflCode(options: SeflGenOptions): Instruction =
    option.seflCode(options)
}

object CtTarget extends BaseParsers {
  import ParserMP.monadPlusSyntax._

  def parser: Parser[Target] =
    for {
      _ <- iptParsers.jumpOptionParser

      // Parse the actual name of the target.
      targetName <- someSpacesParser >> identifierParser if targetName == "CT"

      // Parse target's options.
      option <- someSpacesParser >> oneOf(noTrackParser)
    } yield CtTarget(option)

  sealed trait Option extends Target

  // --notrack Disables connection tracking for this packet.
  private case class NoTrackOption() extends Option {
    type Self = this.type

    override def seflCode(options: SeflGenOptions): Instruction = {
      val ctstateTag = virtdev.ctstateTag(options.deviceId)
      Assign(ctstateTag, ConstantValue(ConnectionState.Untracked.id))
    }
  }

  private def noTrackParser: Parser[Option] =
    for {
      _ <- parseString("--notrack")
    } yield NoTrackOption()
}
