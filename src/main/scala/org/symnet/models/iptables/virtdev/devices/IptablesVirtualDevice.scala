// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet
package models.iptables
package virtdev

package object devices {
  // For now this is just an alias for a Regular VD to differentiate it from
  // other regular VDs (e.g. forwarding tables).
  type IptablesVirtualDevice[+Config] = RegularVirtualDevice[Config]
}
