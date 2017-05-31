// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet.models.iptables.virtdev.devices

package object ivds {
  ///
  /// Constants used only in the `ivds' package.
  ///

  def AcceptTagValue = Int.MaxValue


  ///
  /// Various utility functions used only in the `ivds' package.
  ///

  def mapIf[K, V](cond: Boolean, k: => K, v: => V): Map[K, V] =
    if (cond) Map(k -> v) else Map.empty
}
