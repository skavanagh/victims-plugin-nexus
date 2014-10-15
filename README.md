victims-plugin-nexus
======

About
-----
Nexus plugin to prevent distribution of vulnerable artifacts when running maven. (for more info on Victims https://github.com/victims)

Prerequisites
-------------
Java JDK 1.7 
http://www.oracle.com/technetwork/java/javase/overview/index.html

Apache Maven 3.0.4 or 3.0.5 (the newer versions of maven will NOT work!!)
http://maven.apache.org/download.cgi

victims-lib >= 1.4-SNAPSHOT
https://github.com/victims/victims-lib-java

Nexus
http://www.sonatype.org/nexus/go/

Build and Install
-----------------
Export environment variables

    export JAVA_HOME=/path/to/jdk
    export M2_HOME=/path/to/maven
    export PATH=$JAVA_HOME/bin:$M2_HOME/bin:$PATH

Download, build, and install victims-lib

    cd victims-lib-java
    mvn clean package install

Build victims-plugin-nexus

    cd victims-plugin-nexus
    mvn clean package

Unzip `victims-plugin-nexus-2.10.0-02-bundle.zip` in the `$NEXUS_HOME/nexus/WEB-INF/plugin-repository`
directory and restart nexus

Author
------
**Sean Kavanagh** 

+ sean.p.kavanagh6@gmail.com
+ https://twitter.com/spkavanagh6
