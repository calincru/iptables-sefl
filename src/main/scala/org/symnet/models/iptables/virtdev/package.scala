// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet
package models.iptables

/** An iptables enhanced router is built as follows:
 *
 *     +--------------------------------------------------+
 *  --o|--111-----+                                +------|o--
 *     |          |       +----LLL-----+           |      |
 *     |          |       |            |           |      |
 *  --o|--111----222---333+---444---555+--666---777+------|o--
 *   . |          |                                .  .   | .
 *   . |          |                                .  .   | .
 *  --o|--111-----+                                +------|o--
 *     +--------------------------------------------------+
 *
 *
 *  --o -- these are input/output ports
 *  LLL -- this is the local process; it usually acts as a sink (simply drops
 *         the packets)
 *  111 -- these are the VDs that set the input interface as a metadata in the
 *         packet.
 *  222 -- this is the PREROUTING chain.
 *  333 -- this is the first routing decision; it either sends the packets to a
 *         local process or determines the output interface of the packet and
 *         stores it as a metadata.
 *  444 -- this is the FORWARDING chain.
 *  555 -- this is the second (and final) routing decision; it works the same as
 *         the previous one.
 *  666 -- this is the POSTROUTING chain.
 *  777 -- this is where the actual dispatching is done (fork - forward).
 */

package object virtdev {
  type Port = String
  type Instruction = org.change.v2.analysis.processingmodels.Instruction

  val InputDispatchTag  = "input-dispatch"
  val OutputDispatchTag = "output-dispatch"
}
