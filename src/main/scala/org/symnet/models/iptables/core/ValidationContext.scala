// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet
package models.iptables
package core

import virtdev.{Port => Interface}

case class ValidationContext(
    table: Option[Table],
    chain: Option[Chain],
    rule: Option[Rule],
    interfaces: List[Interface]) {

  def setTable(newTable: Table): ValidationContext =
    ValidationContext(Some(newTable), chain, rule, interfaces)

  def setChain(newChain: Chain): ValidationContext =
    ValidationContext(table, Some(newChain), rule, interfaces)

  def setRule(newRule: Rule): ValidationContext =
    ValidationContext(table, chain, Some(newRule), interfaces)

  def setInterfaces(newInterfaces: List[Interface]): ValidationContext =
    ValidationContext(table, chain, rule, newInterfaces)
}

object ValidationContext {
  def empty: ValidationContext =
    ValidationContext(None, None, None, Nil)
}
