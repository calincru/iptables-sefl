// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet.models.iptables
package core

import virtdev.{Port => Interface}

trait SeflGenOptions {
  val acceptPort: Interface
  val dropPort:   Interface
  val returnPort: Interface
  val jumpPort:   Interface

  val portsMap: Map[String, Int]
}
