// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet
package models.iptables
package extensions.comment

// scala
import org.junit.runner.RunWith
import org.scalatest.{FunSuite, Matchers}
import org.scalatest.junit.JUnitRunner

// 3rd-party
// -> scalaz
import scalaz.Maybe._

// project
// -> core
import core._
import core.iptParsers.ruleParser

@RunWith(classOf[JUnitRunner])
class CommentSuite extends FunSuite with Matchers {

  // TODO: Add more tests once we have the logic for dynamically adding
  // extensions while parsing.

  test("simple comment rule with extension explicitly added") {
    implicit val context =
      ParsingContext.default.addMatchExtension(CommentExtension)

    // NOTE: All these tests fail if we only add the module loader, since we
    // don't specify "-m comment".
    ruleParser.eval("--comment \"Jumping to user-chain..\" -j USER_CHAIN") shouldBe a [Just[_]]
    ruleParser.eval("""-s 192.168.0.0/24
                       -i eth0
                       --comment "This rule matches private traffic"
                       -j ACCEPT""") shouldBe a [Just[_]]
  }
}
