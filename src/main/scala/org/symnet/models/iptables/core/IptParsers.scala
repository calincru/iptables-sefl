// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet
package models.iptables
package core

object iptParsers extends BaseParsers {
  import ParserMP.monadPlusSyntax._

  ///
  /// Target, rule, chain and table parsers.
  ///

  def jumpOptionParser: Parser[String] =
    spacesParser >> oneOf(parseString("-j"), parseString("--jump"))

  def gotoOptionParser: Parser[String] =
    spacesParser >> oneOf(parseString("-g"), parseString("--goto"))

  /** Chain target parser.
   *
   *  This parser is used as the solution of last resort when matching targets
   *  in a rule, and the parsed target name should refer to the name of another
   *  chain.
   *
   *  This is ensured at a later stage, when the entire parsing is complete, to
   *  allow forward references.
   *
   *  NOTE: The rule parser (see above) containing it should be added last to
   *  the list of rule parsers as part of the parsing context if support for
   *  jumps to other chains is needed.
   *
   *  TODO(calincru): Add factory helper for this.
   */
  def chainTargetParser: Parser[Target] =
    for {
      jump       <- oneOf(jumpOptionParser, gotoOptionParser)
      targetName <- someSpacesParser >> identifierParser
    } yield PlaceholderTarget(targetName, List("-g", "--goto").contains(jump))

  /** Helper implementation of a optionless target parser.
   *
   *  Other specialized target parsers can often be easily implemented by simply
   *  providing a mapping of target names and the actual target object from the
   *  iptables model.
   */
  def optionlessTargetParser(
      nameToTarget: Map[String, Target]): Parser[Target] = {
    for {
      _          <- jumpOptionParser
      targetName <- someSpacesParser >> identifierParser
        if nameToTarget contains targetName
    } yield nameToTarget(targetName)
  }

  def moduleLoaderParser[T <: Match](moduleName: String, t: T): Parser[Match] =
    for {
      _ <- spacesParser >> parseString("-m") >> someSpacesParser >>
            parseString(moduleName)
    } yield t

  // TODO: Change the way it works to support 'matches' that enable other ones,
  // such as '-m mark' or '-p tcp'. It can be implemented by adding a new method
  // to the 'Match' class to return a list of extensions enabled, which will
  // afterwards be added to the context.
  def ruleParser(implicit context: ParsingContext): Parser[Rule] = {
    val matchParsers  = context.matchExtensions.map(_.matchParsers).flatten
    val targetParsers = context.targetExtensions.map(_.targetParser)

    for {
      matches <- many(oneOf(matchParsers: _*))
      target  <- oneOf(targetParsers: _*)
    } yield Rule(matches, target)
  }

  def chainParser(implicit context: ParsingContext): Parser[Chain] =
    for {
      chainName   <- spacesParser >> parseChar('<') >> identifierParser
      maybePolicy <- optional(parseChar(':') >> identifierParser)
      _           <- parseChar('>')
      rules       <- many(ruleParser)
    } yield (maybePolicy match {
      case Some(p) if Policy(p).isDefined =>
        BuiltinChain(chainName, rules, Policy(p).get)
      case None =>
        UserChain(chainName, rules)
    })

  def tableParser(implicit context: ParsingContext): Parser[Table] =
    for {
      _ <- spacesParser >> parseString("<<")
      tableName <- identifierParser
      _ <- spacesParser >> parseString(">>")
      chains    <- many(chainParser)
    } yield Table(tableName, chains)
}
