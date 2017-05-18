// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet
package models.iptables.virtdev
package devices
package ivds

import org.change.v2.analysis.processingmodels.instructions.{Fail, Forward, If}

import models.iptables.core.{Rule, SeflCondition, SeflGenOptions}

trait ContiguousIVDConfig {
  val id:       String
  val rules:    List[Rule]
  val portsMap: Map[String, Int]
}

case class ContiguousIVD(
    name:   String,
    config: ContiguousIVDConfig)
  extends RegularVirtualDevice[ContiguousIVDConfig](
    name,
      // single input port
    1,
      // 5 output ports:
      //  * 0 - ACCEPT output port
      //  * 1 - DROP output port
      //  * 2 - RETURN output port
      //  * 3 - towards its corresponding user-defined chain
      //  * 4 - next contiguous IVD
    5,
    config) { self =>

  def inputPort:   Port = inputPort(0)
  def acceptPort:  Port = outputPort(0)
  def dropPort:    Port = outputPort(1)
  def returnPort:  Port = outputPort(2)
  def jumpPort:    Port = outputPort(3)
  def nextIVDport: Port = outputPort(4)

  // TODO: There might be room for optimization here, in terms of generated Sefl
  // code.
  override def portInstructions: Map[Port, Instruction] = {
    val seflGenOptions = new SeflGenOptions {
      val id = config.id

      val acceptPort = self.acceptPort
      val dropPort   = self.dropPort
      val returnPort = self.returnPort
      val jumpPort   = self.jumpPort

      val portsMap = config.portsMap
    }

    // This function nests multiple Sefl If statements to implement
    // conjunction.
    val combineConstraints = (conditions: List[SeflCondition],
                              thenStmnt:  Instruction,
                              elseStmnt:  Instruction) =>
      conditions.foldRight(thenStmnt)((condition, acc) => {
        val constraints = condition.constraints

        if (condition.conjunction) {
          // If this is a conjunction, we do:
          //
          //    if (cond1)
          //      if(cond2)
          //        ...
          //      else
          //        ...
          //    else
          //      elseStmnt
          //
          constraints.foldRight(acc)((constraint, acc_inner) =>
              If(constraint, acc_inner, elseStmnt))
        } else {
          // If this is a disjunction, we do:
          //
          //    if (cond1)
          //      thenStmnt
          //    else if (cond2)
          //      thenStmnt
          //    ....
          //    else
          //      elseStmnt
          //
          constraints.foldRight(elseStmnt)((constraint, acc_inner) =>
              If(constraint, thenStmnt, acc_inner))
        }
      })

    // This is the default instruction if no rule matches.
    val defaultInstr: Instruction = Forward(nextIVDport)

    List(
      // Generate input port instructions.
      //
      // NOTE: The direction of the fold matters here: iptables lookup is done
      // from top to bottom which maps to right-associativity in our processing.
      Map(inputPort -> config.rules.foldRight(defaultInstr)((rule, acc) =>
        combineConstraints(rule.matches.map(_.seflCondition(seflGenOptions)),
                           rule.target.seflCode(seflGenOptions),
                           acc))),

      // Fail if the drop port is reached.
      Map(dropPort -> Fail(s"Packet dropped by $name"))
    ).flatten.toMap
  }
}
