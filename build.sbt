organization := "com.alexdupre"

name := "litecoin-lib"

version := "0.9.18-SNAPSHOT"

crossScalaVersions := Seq("2.11.12", "2.12.6")

scalaVersion := "2.12.6"

scalacOptions ++= Seq("-deprecation", "-feature", "-language:implicitConversions,postfixOps")

libraryDependencies ++= Seq(
  "com.madgag.spongycastle" % "core" % "1.58.0.0",
  "com.google.protobuf" % "protobuf-java" % "2.5.0",
  "org.slf4j" % "slf4j-api" % "1.7.25",
  "ch.qos.logback" % "logback-classic" % "1.2.3" % "test",
  "com.google.guava" % "guava" % "19.0" % "test",
  "org.scalatest" %% "scalatest" % "3.0.3" % "test",
  "org.json4s" %% "json4s-jackson" % "3.5.2" % "test",
  "junit" % "junit" % "4.12" % "test",
)


lazy val gitSubmoduleUpdateTask = TaskKey[Unit]("gitSubmoduleUpdate", "Updates git sub-modules")
gitSubmoduleUpdateTask := {
  import sys.process._
  Seq("git", "submodule", "update", "--init", "--recursive") !
}

compile in Compile := (compile in Compile).dependsOn(gitSubmoduleUpdateTask).value

unmanagedSourceDirectories in Compile += baseDirectory.value / "secp256k1" / "src"

publishMavenStyle := true

publishTo := {
  val nexus = "https://oss.sonatype.org/"
  if (isSnapshot.value)
    Some("snapshots" at nexus + "content/repositories/snapshots")
  else
    Some("releases" at nexus + "service/local/staging/deploy/maven2")
}

pomIncludeRepository := { _ =>
  false
}

pomExtra := (<url>https://github.com/alexdupre/litecoin-lib</url>
  <licenses>
    <license>
      <name>Apache 2</name>
      <url>https://www.apache.org/licenses/LICENSE-2.0.txt</url>
      <distribution>repo</distribution>
    </license>
  </licenses>
  <scm>
    <url>git@github.com:alexdupre/litecoin-lib.git</url>
    <connection>scm:git:git@github.com:alexdupre/litecoin-lib.git</connection>
  </scm>
  <developers>
    <developer>
      <id>alexdupre</id>
      <name>Alex Dupre</name>
      <url>http://www.alexdupre.com</url>
    </developer>
  </developers>)
