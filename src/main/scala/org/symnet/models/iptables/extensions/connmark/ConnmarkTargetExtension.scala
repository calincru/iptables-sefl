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
import org.change.v2.analysis.expression.concrete.nonprimitive.{:@, <^>, <&>}
import org.change.v2.analysis.processingmodels.Instruction
import org.change.v2.analysis.processingmodels.instructions._

// -> scalaz
import scalaz.Maybe

// project
import core._

object ConnmarkTargetExtension extends TargetExtension {
  val targetParser = ConnmarkTarget.parser
}

case class ConnmarkTarget(option: ConnmarkTarget.TargetOption) extends Target {
  type Self = option.Self

  override def validate(context: ValidationContext): Maybe[Self] =
    option.validate(context)

  override def seflCode(options: SeflGenOptions): Instruction =
    option.seflCode(options)
}

object ConnmarkTarget extends BaseParsers {
  import ParserMP.monadPlusSyntax._

  def parser: Parser[Target] =
    for {
      _ <- iptParsers.jumpOptionParser

      // Parse the target name.
      targetName <- someSpacesParser >> identifierParser
        if targetName == "CONNMARK"

      // Parse target's options.
      option <- someSpacesParser >> oneOf(setXmarkOptionParser,
                                          saveMarkOptionParser,
                                          restoreMarkOptionParser)
    } yield ConnmarkTarget(option)

  sealed trait TargetOption extends Target


  // --set-xmark value[/mask]
  //
  //    Zero out the bits given by mask and XOR value into the ctmark.
  private case class SetXmarkOption(
      value: Long,
      maybeMask: Option[Long]) extends TargetOption {
    type Self = this.type

    override def seflCode(options: SeflGenOptions): Instruction = {
      val nfmarkTag = virtdev.nfmarkTag(options.deviceId)
      val mask = maybeMask getOrElse 0xFFFFFFFFL

      Assign(nfmarkTag,
             <^>(ConstantBitVector(value),
                 <&>(:@(nfmarkTag), ConstantBitVector(mask))))
    }
  }

  // --save-mark [--nfmask nfmask] [--ctmask ctmask]
  //
  //    Copy the packet mark (nfmark) to the connection mark (ctmark) using the
  //    given masks. The new nfmark value is determined as follows:
  //
  //        ctmark = (ctmark & ~ctmask) ^ (nfmark & nfmask)
  //
  //    i.e. ctmask defines what bits to clear and nfmask what bits of the
  //    nfmark to XOR into the ctmark. ctmask and nfmask default to 0xFFFFFFFF.
  private case class SaveMarkOption(
      maybeNfmask: Option[Long],
      maybeCtmask: Option[Long]) extends TargetOption {
    type Self = this.type

    override def seflCode(options: SeflGenOptions): Instruction = {
      val nfmarkTag = virtdev.nfmarkTag(options.deviceId)
      val ctmarkTag = virtdev.ctmarkTag(options.deviceId)
      val nfmask = maybeNfmask getOrElse 0xFFFFFFFFL
      val ctmask = maybeCtmask getOrElse 0xFFFFFFFFL

      Assign(ctmarkTag,
             <^>(<&>(:@(ctmarkTag), ConstantBitVector(~ctmask)),
                 <&>(:@(nfmarkTag), ConstantBitVector(nfmask))))
    }
  }

  // --restore-mark [--nfmask nfmask] [--ctmask ctmask]
  //
  //    Copy the connection mark (ctmark) to the packet mark (nfmark) using the
  //    given masks. the new ctmark value is determined as follows:
  //
  //      nfmark = (nfmark & ~nfmask) ^ (ctmark & ctmask);
  //
  //    i.e. nfmask defines what bits to clear and ctmask what bits of the
  //    ctmark to xor into the nfmark. ctmask and nfmask default to 0xffffffff.
  private case class RestoreMarkOption(
      maybeNfmask: Option[Long],
      maybeCtmask: Option[Long]) extends TargetOption {
    type Self = this.type

    override protected def validateIf(context: ValidationContext): Boolean =
      // --restore-mark is only valid in the mangle table.
      context.table.get.name == "mangle"

    override def seflCode(options: SeflGenOptions): Instruction = {
      val nfmarkTag = virtdev.nfmarkTag(options.deviceId)
      val ctmarkTag = virtdev.ctmarkTag(options.deviceId)
      val nfmask = maybeNfmask getOrElse 0xFFFFFFFFL
      val ctmask = maybeCtmask getOrElse 0xFFFFFFFFL

      Assign(nfmarkTag,
             <^>(<&>(:@(nfmarkTag), ConstantBitVector(~nfmask)),
                 <&>(:@(ctmarkTag), ConstantBitVector(ctmask))))
    }
  }

  private def setXmarkOptionParser: Parser[TargetOption] =
    for {
      optionName <- parseString("--set-xmark")
      value <- someSpacesParser >> hexLongParser
      maybeMask <- optional(parseChar('/') >> hexLongParser)
    } yield SetXmarkOption(value, maybeMask)

  private def saveMarkOptionParser: Parser[TargetOption] =
    for {
      optionName <- parseString("--save-mark")
      nfmask <- optional(someSpacesParser >> parseString("--nfmask") >>
                         someSpacesParser >> hexLongParser)
      ctmask <- optional(someSpacesParser >> parseString("--ctmask") >>
                         someSpacesParser >> hexLongParser)
    } yield SaveMarkOption(nfmask, ctmask)

  private def restoreMarkOptionParser: Parser[TargetOption] =
    for {
      optionName <- parseString("--restore-mark")
      nfmask <- optional(someSpacesParser >> parseString("--nfmask") >>
                         someSpacesParser >> hexLongParser)
      ctmask <- optional(someSpacesParser >> parseString("--ctmask") >>
                         someSpacesParser >> hexLongParser)
    } yield RestoreMarkOption(nfmask, ctmask)
}
