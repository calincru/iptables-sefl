// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet
package models.iptables
package virtdev
package visitors

import devices._

class NetworkModelBuilder(nm: NetworkModel) extends VirtualDeviceVisitor {

  // For regular device we just add them to the network model.
  def visit(rvd: RegularVirtualDevice[_]): NetworkModel = nm.addDevice(rvd)
}
