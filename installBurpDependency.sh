#!/bin/sh

/usr/share/netbeans/java/maven/bin/mvn install:install-file -Dfile="/opt/BurpSuitePro/burpsuite_pro.jar" -DgroupId=NonHTTPProxy.burp -DartifactId=burp -Dversion=2020.2 -Dpackaging=jar
