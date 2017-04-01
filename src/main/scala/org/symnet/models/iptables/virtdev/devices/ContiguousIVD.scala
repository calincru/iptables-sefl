// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet
package models.iptables.virtdev
package devices

import models.iptables.core.Rule

// TODO
case class ContiguousIVD(
    name: String,
    rules: List[Rule])
  extends RegularVirtualDevice[Unit](
    name,
    1,
    2,
    ()) {

  // TODO
  override def portInstructions: Map[Port, Instruction] = Map.empty
}
