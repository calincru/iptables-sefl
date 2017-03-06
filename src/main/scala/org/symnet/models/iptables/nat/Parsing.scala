// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet
package models.iptables
package filter

import core.{Match, Parsing, RuleParser, Target}
import types.net.Ipv4

object NatParser extends RuleParser {
  val matchParsers  = Nil
  val targetParsers = Nil

  private object Impl {
    import Parsing._
    import Parsing.ParserMP.monadPlusSyntax._

    // TODO(calincru): Implement this.
  }
}
