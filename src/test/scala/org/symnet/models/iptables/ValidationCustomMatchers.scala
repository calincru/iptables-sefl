// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet
package models.iptables

// 3rd party:
// -> scalatest
import org.scalatest._
import matchers._

// -> scalaz
import scalaz.Maybe

// project
import core.{IptElement, ValidationContext}

trait ValidationCustomMatchers {

  type ParsingResult = Maybe[(String, T)] forSome {type T <: IptElement}

  val consumeInput = new Matcher[ParsingResult] {
    def apply(left: ParsingResult) = MatchResult(
      left.isJust && left.toOption.get._1.trim.isEmpty,
      s"$left did not consume all input",
      s"$left consumed all input"
    )
  }

  val beValid = new Matcher[ParsingResult] {
    def apply(left: ParsingResult) = MatchResult(
      left.isJust &&
        left.toOption.get._2.validate(ValidationContext.empty).isJust,
      s"$left is not valid",
      s"$left is valid"
    )
  }
}
