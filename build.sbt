organization := "org.symnet"
version := "0.1"

scalaVersion := "2.12.1"
scalacOptions := Seq("-deprecation", "utf8")

libraryDependencies ++= {
  Seq(
    "junit" % "junit" % "4.4" % "test",
    "org.scalactic" %% "scalactic" % "3.0.1",
    "org.scalatest" %% "scalatest" % "3.0.1" % "test"
  )
}
