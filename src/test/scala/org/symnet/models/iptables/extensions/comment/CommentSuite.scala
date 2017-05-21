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

  test("simple comment rule with extension explicitly added") {
    implicit val context = ParsingContext.default

    {
      val maybeResult = ruleParser.apply("""
        -m comment --comment "Jumping to user-chain.."
        -j USER_CHAIN
      """)
      maybeResult shouldBe a [Just[_]]

      val (state, result) = maybeResult.toOption.get
      state.trim shouldBe empty
    }
    {
      val maybeResult = ruleParser.apply("""
        -s 192.168.0.0/24
        -i eth0
        -m comment --comment "This rule matches private traffic"
        -j ACCEPT
      """)
      maybeResult shouldBe a [Just[_]]

      val (state, result) = maybeResult.toOption.get
      state.trim shouldBe empty
    }
  }
}
