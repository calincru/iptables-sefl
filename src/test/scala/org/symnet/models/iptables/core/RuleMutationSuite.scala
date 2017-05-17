// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet
package models.iptables
package core

// scala
import org.junit.runner.RunWith
import org.scalatest.{FunSuite, Matchers}
import org.scalatest.junit.JUnitRunner

// project
import extensions.filter._


@RunWith(classOf[JUnitRunner])
class RuleMutationSuite extends FunSuite with Matchers {

  test("simple in interface plus") {
    val rule = Rule(List(InInterfaceMatch("eth", true)), AcceptTarget)
    rule.mutate(List("eth0", "eth1")) should have length (2)
  }

  test("simple out interface plus") {
    val rule = Rule(List(OutInterfaceMatch("qr-", true)), AcceptTarget)
    rule.mutate(List("eth0", "qr-dhcp1", "qr-dhcp2", "qr-compute-node")) should
      have length (3)
  }

  test("empty matches results in no rules") {
    val rule = Rule(List(InInterfaceMatch("eth", true)), DropTarget)
    rule.mutate(Nil) should be (empty)
  }
}
