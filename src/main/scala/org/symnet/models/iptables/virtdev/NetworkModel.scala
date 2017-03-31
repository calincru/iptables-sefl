// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet
package models.iptables
package virtdev

/** A 'NetworkModel' aggregates multiple devices alongside the links between
 *  them.
 *
 *  It can be passed to an executor to trace the flows through the modeled
 *  network.
 */
trait NetworkModel
