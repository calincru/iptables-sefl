// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet.types

// Network related types.
object Net {
  final class Ipv4(val host: Long, val mask: Option[Int] = None) {
    override def toString =
      List((host & 0xff000000) >> 24,
           (host & 0x00ff0000) >> 16,
           (host & 0x0000ff00) >> 8,
           (host & 0x000000ff) >> 0).mkString(".") + (mask match {
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
    def apply(b0: Int, b1: Int, b2: Int, b3: Int, mask: Option[Int] = None) =
      new Ipv4((b0 << 24) + (b1 << 16) + (b2 << 8) + (b3 << 0), mask)
  }
}
