// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet
package models.iptables

import org.change.v2.analysis.expression.concrete.ConstantValue
import org.change.v2.analysis.memory.Tag
import org.change.v2.analysis.processingmodels.instructions.{Assign, Allocate, InstructionBlock}

package object virtdev {
  type Port = String
  type Instruction = org.change.v2.analysis.processingmodels.Instruction

  val InputDispatchTag  = "input-dispatch"
  val OutputDispatchTag = "output-dispatch"

  val InputDispatchTagInitializer =
    InstructionBlock(Allocate(InputDispatchTag),
                     Assign(InputDispatchTag, ConstantValue(0)))

}
