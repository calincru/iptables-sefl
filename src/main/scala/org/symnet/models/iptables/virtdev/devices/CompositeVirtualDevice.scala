// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet
package models.iptables
package virtdev
package devices

abstract class CompositeVirtualDevice[+Config](
    name:         String,
    inputPorts:   Int,
    outputPorts:  Int,
    config:       Config)
  extends VirtualDevice[Config](name, inputPorts, outputPorts, config)
