// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet
package models.iptables.virtdev
package visitors

import devices._

abstract class VirtualDeviceVisitor {
  // This shouldn't really get called.
  def visit(vd:  VirtualDevice[_]): Any = null

  def visit(rvd: RegularVirtualDevice[_]): Any
}
