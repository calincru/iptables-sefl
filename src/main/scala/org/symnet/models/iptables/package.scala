// Copyright (C) 2017 Calin Cruceru <calin.cruceru@stud.acs.upb.ro>.
//
// See the LICENCE file distributed with this work for additional
// information regarding copyright ownership.

package org.symnet.models

import scalaz.{Applicative, Functor, Traverse}

package object iptables {
    implicit def charListToString(chars: List[Char]): String = chars.mkString

    implicit def liftConversionToFunctor[F[_], A,  B]
        (fa: F[A])
        (implicit f: (A) => B, functor: Functor[F]): F[B] = functor.map(fa)(f)

    implicit val listScalazInstances: Traverse[List] = new Traverse[List] {

      def traverseImpl[F[_], A, B]
          (fa: List[A])
          (f: A => F[B])
          (implicit F: Applicative[F]): F[List[B]] =
        fa.foldRight(F.point(List.empty[B]))((a, fbs) => F.apply2(f(a), fbs)(_ :: _))
    }
}
