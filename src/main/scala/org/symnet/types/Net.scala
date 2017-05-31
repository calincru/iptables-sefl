// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet.types

package object net {
  // Network related types.
  final class Ipv4(val host: Long, val mask: Option[Int] = None) {
    def toHostRange: (Ipv4, Ipv4) =
      if (!mask.isDefined) {
        (this, this)
      } else {
        val m = mask.get
        val addr = 32 - m
        val lowerMask = Long.MaxValue << addr
        val higherMask = Long.MaxValue >>> (m + 31)

        (new Ipv4(host & lowerMask), new Ipv4(host | higherMask))
      }

    override def toString: String =
      List((host & 0xff000000) >>> 24,
           (host & 0x00ff0000) >>> 16,
           (host & 0x0000ff00) >>> 8,
           (host & 0x000000ff) >>> 0).mkString(".") + (mask match {
        case Some(m) => "/" + m.toString
        case       _ => ""
      })

    override def equals(that: Any): Boolean =
      that match {
        case that: Ipv4 => this.hashCode == that.hashCode
        case _          => false
      }

    override def hashCode: Int = {
      val prime = 31
      var result = 1
      result = prime * result + host.hashCode
      result = prime * result + mask.hashCode
      result
    }
  }

  object Ipv4 {
    def apply(
        b0: Int,
        b1: Int,
        b2: Int,
        b3: Int,
        mask: Option[Int] = None): Ipv4 = {
      val validByte = (b: Int) => b >= 0 && b <= 255
      assert(validByte(b0) && validByte(b1) && validByte(b2) && validByte(b3))

      new Ipv4((b0.toLong << 24) + (b1 << 16) + (b2 << 8) + (b3 << 0), mask)
    }
  }

  type Port = Int
  type PortRange = (Port, Port)
}
