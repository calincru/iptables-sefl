organization := "org.symnet"
version := "0.1"

scalaVersion := "2.12.1"
scalacOptions := Seq(
  "-deprecation",
  "-feature",
  "-language:implicitConversions",
  "-language:higherKinds",
  "utf8"
)

coverageEnabled := true

import org.scoverage.coveralls.Imports.CoverallsKeys._
coverallsTokenFile := Some(".coveralls_token")

val scalazVersion = "7.2.9"

libraryDependencies ++= {
  Seq(
    "junit" % "junit" % "4.4" % "test",
    "org.scalactic" %% "scalactic" % "3.0.1",
    "org.scalatest" %% "scalatest" % "3.0.1" % "test",

    // scalaz
    "org.scalaz" %% "scalaz-core" % scalazVersion,
    "org.scalaz" %% "scalaz-effect" % scalazVersion,
    "org.scalaz" %% "scalaz-scalacheck-binding" % scalazVersion % "test"
  )
}
