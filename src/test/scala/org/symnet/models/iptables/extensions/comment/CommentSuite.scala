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
class CommentSuite extends FunSuite with Matchers
                                    with ValidationCustomMatchers {

  test("simple comment rule with extension explicitly added") {
    implicit val context = ParsingContext.default

    ruleParser.apply("""
      -m comment --comment "Jumping to user-chain.."
      -j USER_CHAIN
    """) should consumeInput

    ruleParser.apply("""
      -s 192.168.0.0/24
      -i eth0
      -m comment --comment "This rule matches private traffic"
      -j ACCEPT
    """) should consumeInput
  }
}
