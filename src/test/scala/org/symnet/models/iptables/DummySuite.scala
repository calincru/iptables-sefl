package org.symnet.models.iptables

import org.junit.runner.RunWith
import org.scalatest.FunSuite
import org.scalatest.junit.JUnitRunner

import Dummy._

/**
 * Dummy test suite module used to test the initial repo configs.
 */
@RunWith(classOf[JUnitRunner])
class DummySuite extends FunSuite {
  test("dummy test") {
    assert(dummySum(1, 2) === 3)
  }
}
