// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet
package models.iptables
package filter

// scala
import org.junit.runner.RunWith
import org.scalatest.{FunSuite, Matchers}
import org.scalatest.junit.JUnitRunner

// 3rd party: scalaz
import scalaz.Maybe._

// project
// -> core
import core.{Parsing, ParsingContext}
import Parsing.{ruleParser, chainParser}
import Parsing.Combinators._

// -> types
import types.net._

@RunWith(classOf[JUnitRunner])
class SnatTargetExtensionSuite extends FunSuite with Matchers {
  import SnatTargetExtension.Impl._
  // TODO(calincru)
}

@RunWith(classOf[JUnitRunner])
class DnatTargetExtensionSuite extends FunSuite with Matchers {
  import DnatTargetExtension.Impl._
  // TODO(calincru)
}

@RunWith(classOf[JUnitRunner])
class MasqueradeTargetExtensionSuite extends FunSuite with Matchers {
  import DnatTargetExtension.Impl._
  // TODO(calincru)
}
