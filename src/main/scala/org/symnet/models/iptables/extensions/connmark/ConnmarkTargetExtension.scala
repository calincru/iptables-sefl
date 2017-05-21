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

case class ConnmarkTarget(param: ConnmarkTarget.Param) extends Target {
  type Self = param.Self

  override def validate(context: ValidationContext): Maybe[Self] =
    param.validate(context)

  override def seflCode(options: SeflGenOptions): Instruction =
    param.seflCode(options)
}

object ConnmarkTarget extends BaseParsers {
  import ParserMP.monadPlusSyntax._

  def parser: Parser[Target] =
    for {
      _ <- iptParsers.jumpOptionParser

      // Parse the target name.
      targetName <- someSpacesParser >> identifierParser
        if targetName == "CONNMARK"

      // Parse target's parameter.
      param <- someSpacesParser >> oneOf(setOptionParser,
                                         saveOptionParser,
                                         restoreOptionParser)
    } yield ConnmarkTarget(param)

  sealed trait Param extends Target


  // --set-xmark value[/mask]
  //
  //    Zero out the bits given by mask and XOR value into the ctmark.
  private case class SetParam(
      value: Long,
      maybeMask: Option[Long]) extends Param {
    type Self = this.type

    override def seflCode(options: SeflGenOptions): Instruction = {
      val nfmark = virtdev.nfmarkTag(options.id)
      val mask = maybeMask getOrElse 0xFFFFFFFFL

      InstructionBlock(
        Assign(
          nfmark,
          <^>(ConstantBitVector(value),
              <&>(:@(nfmark), ConstantBitVector(mask)))),
        Forward(options.acceptPort)
      )
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
  private case class SaveParam(
      maybeNfmask: Option[Long],
      maybeCtmask: Option[Long]) extends Param {
    type Self = this.type

    override def seflCode(options: SeflGenOptions): Instruction = {
      val nfmark = virtdev.nfmarkTag(options.id)
      val nfmask = maybeNfmask getOrElse 0xFFFFFFFFL
      val ctmask = maybeCtmask getOrElse 0xFFFFFFFFL

      InstructionBlock(
        Assign(
          virtdev.CtmarkTag,
          <^>(<&>(:@(virtdev.CtmarkTag), ConstantBitVector(~ctmask)),
              <&>(:@(nfmark), ConstantBitVector(nfmask)))),
        Forward(options.acceptPort)
      )
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
  private case class RestoreParam(
      maybeNfmask: Option[Long],
      maybeCtmask: Option[Long]) extends Param {
    type Self = this.type

    override protected def validateIf(context: ValidationContext): Boolean =
      // --restore-mark is only valid in the mangle table.
      context.table.get.name == "mangle"

    override def seflCode(options: SeflGenOptions): Instruction = {
      val nfmark = virtdev.nfmarkTag(options.id)
      val nfmask = maybeNfmask getOrElse 0xFFFFFFFFL
      val ctmask = maybeCtmask getOrElse 0xFFFFFFFFL

      InstructionBlock(
        Assign(
          nfmark,
          <^>(<&>(:@(nfmark), ConstantBitVector(~nfmask)),
              <&>(:@(virtdev.CtmarkTag), ConstantBitVector(ctmask)))),
        Forward(options.acceptPort)
      )
    }
  }

  private def setOptionParser: Parser[Param] =
    for {
      optionName <- parseString("--set-xmark")
      value <- someSpacesParser >> hexLongParser
      maybeMask <- optional(parseChar('/') >> hexLongParser)
    } yield SetParam(value, maybeMask)

  private def saveOptionParser: Parser[Param] =
    for {
      optionName <- parseString("--save-mark")
      nfmask <- optional(someSpacesParser >> parseString("--nfmask") >>
                         someSpacesParser >> hexLongParser)
      ctmask <- optional(someSpacesParser >> parseString("--ctmask") >>
                         someSpacesParser >> hexLongParser)
    } yield SaveParam(nfmask, ctmask)

  private def restoreOptionParser: Parser[Param] =
    for {
      optionName <- parseString("--restore-mark")
      nfmask <- optional(someSpacesParser >> parseString("--nfmask") >>
                         someSpacesParser >> hexLongParser)
      ctmask <- optional(someSpacesParser >> parseString("--ctmask") >>
                         someSpacesParser >> hexLongParser)
    } yield RestoreParam(nfmask, ctmask)
}
