// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet
package models.iptables
package virtdev
package visitors

import devices._

abstract class VirtualDeviceVisitor {
  def visit(rvd: RegularVirtualDevice[_]): Any
}
