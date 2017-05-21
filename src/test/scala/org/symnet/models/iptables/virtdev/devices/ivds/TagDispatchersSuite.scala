// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet
package models.iptables
package virtdev
package devices.ivds

// scala
import org.junit.runner.RunWith
import org.scalatest.{FunSuite, Matchers}
import org.scalatest.junit.JUnitRunner

// 3rd party:
// -> Symnet
import org.change.v2.analysis.expression.concrete.ConstantValue
import org.change.v2.analysis.processingmodels.instructions._

@RunWith(classOf[JUnitRunner])
class TagDispatchersSuite
  extends FunSuite with SymnetMisc
                   with Matchers
                   with SymnetCustomMatchers {

  override def deviceId: String = "ipt-router"

  test("validate arguments") {
    an [IllegalArgumentException] should be thrownBy
      InputTagDispatcher("in-dispatcher", 0)

    noException should be thrownBy InputTagDispatcher("in-dispatcher", 1)
    noException should be thrownBy OutputTagDispatcher("out-dispatcher", Nil)
  }

  test("out: no returns, no instructions") {
    val outDisp = OutputTagDispatcher("out-dispatcher", Nil)
    val (success, fail) = symExec(outDisp, outDisp.inputPort)

    success shouldBe empty
    fail shouldBe empty
  }

  test("out: tag not set fails") {
    val outDisp = OutputTagDispatcher("out-dispatcher", List(1, 3))
    val (success, fail) = symExec(outDisp, outDisp.inputPort)

    success shouldBe empty
    fail should have length (2)
  }

  test("in: tag not set fails") {
    val inDisp = InputTagDispatcher("in-dispatcher", 2)
    val (success, fail) = symExec(inDisp, inDisp.inputPort)

    success shouldBe empty
    fail should have length (2)
  }

  test("out: one option, one matched, is forwarded") {
    val outDisp = OutputTagDispatcher("out-dispatcher", List(1))
    val (success, fail) =
      symExec(
        outDisp,
        outDisp.inputPort,
        Assign(OutputDispatchTag, ConstantValue(1))
      )

    fail shouldBe empty
    success should (
      have length (1) and
      containPath (outDisp.inputPort, outDisp.outputPort(0))
    )
  }

  test("in: one option, one matched, is forwarded") {
    val inDisp = InputTagDispatcher("in-dispatcher", 1)
    val (success, fail) =
      symExec(
        inDisp,
        inDisp.inputPort,
        Assign(InputDispatchTag, ConstantValue(0))
      )

    fail shouldBe empty
    success should (
      have length (1) and
      containPath (inDisp.inputPort, inDisp.outputPort(0))
    )
  }

  test("out: two options, one matched") {
    val outDisp = OutputTagDispatcher("out-dispatcher", List(1, 2))
    val (success, fail) =
      symExec(
        outDisp,
        outDisp.inputPort,
        Assign(OutputDispatchTag, ConstantValue(2))
      )

    fail should have length (1)
    success should (
      have length (1) and
      containPath (outDisp.inputPort, outDisp.outputPort(1))
    )
  }

  test("in: three ivds, forward to 3rd") {
    val inDisp = InputTagDispatcher("in-dispatcher", 3)
    val (success, fail) =
      symExec(
        inDisp,
        inDisp.inputPort,
        Assign(InputDispatchTag, ConstantValue(2))
      )

    fail should have length (2)
    success should (
      have length (1) and
      containPath (inDisp.inputPort, inDisp.outputPort(2))
    )
  }
}
