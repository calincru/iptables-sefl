// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet
package models.iptables
package extensions.connmark

// scala
import org.junit.runner.RunWith
import org.scalatest.{FunSuite, Matchers}
import org.scalatest.junit.JUnitRunner

// 3rd party:
// -> scalaz
import scalaz.Maybe._

// project
import core._
import core.iptParsers.{ruleParser, tableParser}
import extensions.filter._

@RunWith(classOf[JUnitRunner])
class ConntrackExtensionSuite extends FunSuite with Matchers {

  test("parsing conntrack match") {
    // TODO: Implement this.
  }
}
