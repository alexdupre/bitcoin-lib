organization := "fr.acinq"

name := "bitcoin-lib"

version := "0.16-SNAPSHOT"

crossScalaVersions := Seq("2.11.12", "2.12.10", "2.13.1")

scalaVersion := "2.13.1"

scalacOptions ++= Seq("-deprecation", "-feature", "-language:implicitConversions,postfixOps", "-unchecked")

libraryDependencies ++= Seq(
  "fr.acinq.bitcoin" % "secp256k1-jni" % "1.2",
  "com.madgag.spongycastle" % "core" % "1.58.0.0",
  "org.scodec" %% "scodec-bits" % "1.1.12",
  "org.slf4j" % "slf4j-api" % "1.7.25",
  "ch.qos.logback" % "logback-classic" % "1.2.3" % "test",
  "com.google.guava" % "guava" % "19.0" % "test",
  "org.scalatest" %% "scalatest" % "3.0.8" % "test",
  "org.json4s" %% "json4s-jackson" % "3.6.7" % "test",
)
