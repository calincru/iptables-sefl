// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.
package org.symnet.models

import scalaz.Functor

package object iptables {
    implicit def charListToString(chars: List[Char]): String = chars.mkString

    implicit def liftConversionToFunctor[F[_], A,  B]
        (fa: F[A])
        (implicit f: (A) => B, functor: Functor[F]): F[B] = functor.map(fa)(f)
}
