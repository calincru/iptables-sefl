// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet
package models.iptables.virtdev
package devices
package ivds

// 3rd-party
// -> Symnet
import org.change.v2.analysis.processingmodels.instructions._

// project
import models.iptables.core.{Rule, SeflCondition, SeflGenOptions}

trait ContiguousIVDConfig {
  val deviceId: String
  val rules:    List[Rule]
  val portsMap: Map[String, Int]
}

case class ContiguousIVD(
    name:   String,
    config: ContiguousIVDConfig)
  extends IptablesVirtualDevice[ContiguousIVDConfig](
    name,
      // no extra input ports
    0,
      // 3 output ports:
      //  * 0 - RETURN output port
      //  * 1 - towards its corresponding user-defined chain
      //  * 2 - next contiguous IVD
    3,
    config) { self =>

  def returnPort:  Port = outputPort(0)
  def jumpPort:    Port = outputPort(1)
  def nextIVDport: Port = outputPort(2)

  // TODO: There might be room for optimization here, in terms of generated Sefl
  // code.
  protected override def ivdPortInstructions: Map[Port, Instruction] = {
    val seflGenOptions = new SeflGenOptions {
      val deviceId = config.deviceId

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
        val initInstr = condition.initInstr

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
          constraints.foldRight(acc)((constraint, acc_inner) => {
            val ifInstr = If(constraint, acc_inner, elseStmnt)

            if (initInstr == NoOp)
              ifInstr
            else
              InstructionBlock(initInstr, ifInstr)
          })
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
          constraints.foldRight(elseStmnt)((constraint, acc_inner) => {
            val ifInstr = If(constraint, thenStmnt, acc_inner)

            if (initInstr == NoOp)
              ifInstr
            else
              InstructionBlock(initInstr, ifInstr)
          })
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
