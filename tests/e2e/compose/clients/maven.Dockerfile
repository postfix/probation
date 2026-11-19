# A Maven client container: the pinned Maven image (3.9.16, Java 21.0.12.1). The stack itself is offline, so the two plugins
# the scenarios run (dependency 3.8.1, deploy 3.1.4) and everything they need are fetched HERE, at image build time, into
# /opt/seed-m2 through a mirror named `probation` (Maven records the id of the repository an artifact came from, and the
# scenarios' mirror has the same id, so the seeded files are accepted as already downloaded from it). At run time the
# package source is the firewall, reached over TLS (the scenarios import the CA into a Java trust store).
ARG MAVEN_IMAGE=docker.io/library/maven:3.9-eclipse-temurin-21
FROM ${MAVEN_IMAGE}
RUN mkdir -p /opt/seed /opt/seed-m2 /opt/seed-repo \
 && printf '%s\n' '<settings><mirrors><mirror><id>probation</id><mirrorOf>*</mirrorOf><url>https://repo.maven.apache.org/maven2/</url></mirror></mirrors></settings>' > /opt/seed/settings.xml \
 && printf '%s\n' '<project><modelVersion>4.0.0</modelVersion><groupId>seed</groupId><artifactId>seed</artifactId><version>1</version><packaging>pom</packaging></project>' > /opt/seed/pom.xml \
 && cd /opt/seed \
 && mvn -B -q -s settings.xml -Dmaven.repo.local=/opt/seed-m2 org.apache.maven.plugins:maven-dependency-plugin:3.8.1:copy-dependencies \
 && mvn -B -q -s settings.xml -Dmaven.repo.local=/opt/seed-m2 org.apache.maven.plugins:maven-deploy-plugin:3.1.4:deploy-file -Dfile=pom.xml -DpomFile=pom.xml -Durl=file:///opt/seed-repo -DrepositoryId=seed \
 && chmod -R a+rX /opt/seed-m2
WORKDIR /work
