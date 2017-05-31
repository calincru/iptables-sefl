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
import org.change.v2.util.canonicalnames._

// project
// -> core
import core._
// -> extensions
import extensions.conntrack.ConnectionState


@RunWith(classOf[JUnitRunner])
class ConnectionTrackingSuite
  extends FunSuite with SymnetFacade
                   with Matchers
                   with SymnetCustomMatchers {
  import VirtdevSuitesCommon._

  override def deviceId: String = "ipt-router"

  test("new to established rewrite") {
    val ivd = ConnectionTrackingIVD("conntrack-ivd", deviceId)
    val (success, fail) =
      symExec(
        ivd,
        ivd.inputPort,
        Assign(ctstate, ConstantValue(ConnectionState.New.id)),
        log = true
      )

    success should (
      have length (1) and
      reachPort (ivd.acceptPort)
    )
    dropped(fail, ivd) shouldBe empty

    success(0) should containAssignment (
      ctstate,
      ConstantValue(ConnectionState.Established.id)
    )
  }
}
