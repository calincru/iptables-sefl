// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet
package models.iptables
package extensions.mark

// 3rd-party
// -> Symnet
import org.change.v2.analysis.expression.concrete.ConstantBitVector
import org.change.v2.analysis.expression.concrete.nonprimitive.{:@, <^>, <|>, <&>}
import org.change.v2.analysis.processingmodels.Instruction
import org.change.v2.analysis.processingmodels.instructions._

// project
import core._

object MarkTargetExtension extends TargetExtension {
  val targetParser = MarkTarget.parser
}

/** This target is used to set the Netfilter mark value associated with the
 *  packet. It can, for example, be used in conjunction with routing based on
 *  fwmark (needs iproute2). If you plan on doing so, note that the mark needs
 *  to be set in the PREROUTING chain of the mangle table to affect routing. The
 *  mark field is 32 bits wide.
 */
case class MarkTarget(
    value: Long,
    maybeMask: Option[Long],
    isXor: Boolean) extends Target {
  type Self = MarkTarget

  override protected def validateIf(context: ValidationContext): Boolean = {
    val chain = context.chain.get
    val table = context.table.get

    // ... note that the mark needs to be set in the PREROUTING chain of the
    // mangle table ...
    table.name == "mangle" && chain.name == "PREROUTING"
  }

  override def seflCode(options: SeflGenOptions): Instruction = {
    val nfmarkTag = virtdev.nfmarkTag(options.id)
    val mask = maybeMask getOrElse 0xFFFFFFFFL
    val op = if (isXor) <^> else <|>

    InstructionBlock(
      Assign(
        nfmarkTag,
        op(ConstantBitVector(value),
           <&>(:@(nfmarkTag), ConstantBitVector(~mask)))),
      Forward(options.acceptPort)
    )
  }
}

object MarkTarget extends BaseParsers {
  import ParserMP.monadPlusSyntax._

  def parser: Parser[Target] =
    for {
      _ <- iptParsers.jumpOptionParser

      // Parse the actual target name.
      targetName <- someSpacesParser >> identifierParser if targetName == "MARK"

      // Parse the options.
      option <- someSpacesParser >> oneOf(parseString("--set-xmark"),
                                          parseString("--set-mark"))

      // Parse 'value[/mask]'.
      // TODO: Change this to a general number (u32) parser.
      value <- someSpacesParser >> hexLongParser
      maybeMask <- optional(parseChar('/') >> hexLongParser)
    } yield MarkTarget(value, maybeMask, option contains 'x')
}
