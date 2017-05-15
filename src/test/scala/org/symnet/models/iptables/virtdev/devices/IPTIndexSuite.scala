// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet
package models.iptables
package virtdev
package devices

// scala
import org.junit.runner.RunWith
import org.scalatest.{FunSuite, Matchers}
import org.scalatest.junit.JUnitRunner

@RunWith(classOf[JUnitRunner])
class IPTIndexSuite extends FunSuite with Matchers with SymnetCustomMatchers {
  import VirtdevSuitesCommon._

  test("chains functions") {
    val filterTable = toTable("""
      <<filter>>
      <FORWARD:DROP>
      <INPUT:DROP>
      <OUTPUT:DROP>

      <CHAIN1>
      <CHAIN2>
      <CHAIN3>
    """)
    val natTable = toTable("""
      <<nat>>
      <PREROUTING:ACCEPT>
      <OUTPUT:ACCEPT>
      <POSTROUTING:ACCEPT>

      <CHAIN1>
      <CHAIN2>
      <CHAIN4>
    """)

    val index = new IPTIndex(List(filterTable, natTable))

    // NAT should be first.
    index.userChains.map(_.name) shouldBe
      List("CHAIN1", "CHAIN2", "CHAIN4", "CHAIN1", "CHAIN2", "CHAIN3")
    index.builtinChains.map(_.name) shouldBe
      List("PREROUTING", "OUTPUT", "POSTROUTING", "FORWARD", "INPUT", "OUTPUT")
  }

  test("adjacency lists") {
    val filterTable = toTable("""
      <<filter>>
      <FORWARD:DROP>
        -p tcp -j CHAIN1
        -p udp -j CHAIN2
        -p all -j ACCEPT

      <INPUT:DROP>
        -p icmp -j CHAIN3

      <OUTPUT:DROP>

      <CHAIN1>
        -s 192.168.1.0/24 -j CHAIN2

      <CHAIN2>
        -i eth0 -j CHAIN3

      <CHAIN3>
    """)
    val index = new IPTIndex(List(filterTable))

    index.outAdjacencyLists.map {
      case (c, cs) => (c.name, cs.map(_.name)) } shouldBe Map(
        "FORWARD" -> Set("CHAIN1", "CHAIN2"),
        "INPUT" -> Set("CHAIN3"),
        "OUTPUT" -> Set(),
        "CHAIN1" -> Set("CHAIN2"),
        "CHAIN2" -> Set("CHAIN3"),
        "CHAIN3" -> Set()
      )

    index.inAdjacencyLists.map {
      case (c, cs) => (c.name, cs.map(_.name)) } shouldBe Map(
        "CHAIN1" -> Set("FORWARD"),
        "CHAIN2" -> Set("FORWARD", "CHAIN1"),
        "CHAIN3" -> Set("INPUT", "CHAIN2"),
        "OUTPUT" -> Set(),
        "INPUT" -> Set(),
        "FORWARD" -> Set()
      )
  }
}
