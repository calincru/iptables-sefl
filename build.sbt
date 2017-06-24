organization := "org.symnet"
name := "iptables-to-sefl"
version := "0.1"

scalaVersion := "2.11.1"
scalacOptions := Seq(
  "-deprecation",
  "-feature",
  "-language:implicitConversions",
  "-language:existentials",
  "-language:higherKinds",
  "utf8"
)

coverageEnabled := true

import org.scoverage.coveralls.Imports.CoverallsKeys._
coverallsTokenFile := Some(".coveralls_token")

val scalazVersion = "7.2.9"

resolvers += "Sonatype OSS Snapshots" at
  "https://oss.sonatype.org/content/repositories/snapshots"

testFrameworks += new TestFramework("org.scalameter.ScalaMeterFramework")
logBuffered := false
parallelExecution in Test := false

javaOptions in run += "-Xmx8G"
fork in run := true

libraryDependencies ++= {
  Seq(
    "junit" % "junit" % "4.4" % "test",
    "org.scalactic" %% "scalactic" % "3.0.1",
    "org.scalatest" %% "scalatest" % "3.0.1" % "test",

    // argument parsing
    "org.rogach" %% "scallop" % "2.1.2",

    // scalameter
    "com.storm-enroute" %% "scalameter" % "0.8.2",

    // scalaz
    "org.scalaz" %% "scalaz-core" % scalazVersion,
    "org.scalaz" %% "scalaz-effect" % scalazVersion,
    "org.scalaz" %% "scalaz-scalacheck-binding" % scalazVersion % "test"
  )
}

mainClass in Compile := Some("org.symnet.models.iptables.Driver")
