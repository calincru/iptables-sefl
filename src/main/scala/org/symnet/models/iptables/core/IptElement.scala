// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet.models.iptables.core

import scalaz.Maybe
import scalaz.Maybe._

trait IptElement {
  type Self <: IptElement

  protected def validateIf(context: ValidationContext): Boolean = true

  def validate(context: ValidationContext): Maybe[Self] =
    if (validateIf(context))
      Just(this.asInstanceOf[Self])
    else
      empty
}
