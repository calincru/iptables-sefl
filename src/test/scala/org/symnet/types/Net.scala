// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet.types.net

import org.junit.runner.RunWith
import org.scalatest.{FunSuite, Matchers}
import org.scalatest.junit.JUnitRunner

@RunWith(classOf[JUnitRunner])
class NetSuite extends FunSuite with Matchers {
  test("ipv4 construction without a mask") {
    val ip = Ipv4(10, 10, 0, 0)
    ip.host shouldBe (10 << 24) + (10 << 16)
    ip.mask shouldBe None
  }

  test("ipv4 construction with a mask") {
    val ip = Ipv4(0, 0, 5, 199, Some(10))
    ip.host shouldBe (5 << 8) + (199 << 0)
    ip.mask shouldBe Some(10)
  }

  test("ipv4 toString") {
    Ipv4(0, 0, 0, 1).toString shouldBe "0.0.0.1"
    Ipv4(255, 255, 255, 0).toString shouldBe "255.255.255.0"
    Ipv4(8, 8, 8, 8, Some(10)).toString shouldBe "8.8.8.8/10"
  }

  test("ipv4 inequality") {
    Ipv4(10, 10, 10, 10, Some(10)) should not be (Ipv4(10, 10, 10, 0))
  }

  test("host range") {
    val (lower, upper) = Ipv4(192, 168, 0, 0, Some(24)).toHostRange

    lower shouldBe Ipv4(192, 168, 0, 0)
    upper shouldBe Ipv4(192, 168, 0, 255)
  }

  test("host range - host part does not matter") {
    val (lower, upper) = Ipv4(192, 168, 0, 12, Some(26)).toHostRange

    lower shouldBe Ipv4(192, 168, 0, 0)
    upper shouldBe Ipv4(192, 168, 0, 63)
  }
}
