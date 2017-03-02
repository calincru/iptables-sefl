// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet.models.iptables.model

import org.symnet.types.Net._

abstract class Match

abstract class IpMatch(ip: Ipv4) extends Match

case class SourceMatch(ip: Ipv4) extends IpMatch(ip)
case class DestinationMatch(ip: Ipv4) extends IpMatch(ip)
