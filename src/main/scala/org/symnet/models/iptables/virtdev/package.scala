// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet
package models.iptables

package object virtdev {
  type Port = String
  type Instruction = org.change.v2.analysis.processingmodels.Instruction

  val IN_DISPATCH_TAG_NAME  = "input-dispatch"
  val OUT_DISPATCH_TAG_NAME = "output-dispatch"
}
