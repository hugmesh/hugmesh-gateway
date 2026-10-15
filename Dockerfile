# HugMesh Gateway — multi-stage build.
#
# Stage 1: build the fat jar with Maven on a JDK image.
# Stage 2: copy the jar onto a slim JRE base so the runtime image
# stays under ~200 MB.
#
# Both base images are pinned by the digest of the multi-arch image index, so a rebuild
# pulls the bytes that were reviewed instead of whatever the tag points at today. The tag
# stays in front of the digest for readability. To move to a newer base, resolve the new
# index digest of each tag (docker buildx imagetools inspect eclipse-temurin:25-jdk) and
# edit both FROM lines. DockerfileBaseImageDigestGuardTest fails the build on a FROM that
# names an image without a digest.

FROM eclipse-temurin:25-jdk@sha256:63f965b560b905c9633218330ac3516304b526a74fdc323a504b05c06e712c30 AS build
WORKDIR /work
COPY mvnw mvnw.cmd ./
COPY .mvn .mvn
COPY pom.xml ./
# CI-only Maven settings (GitHub Packages for hugmesh-commons + hugmesh-parent). Used
# ONLY when the packages_read_token build secret is mounted - see the RUN lines below.
# The compose lane threads its own settings through ENV MAVEN_ARGS (patch-stack-src.sh in
# hugmesh-generator), which is why there is no root settings.xml and no `-s` on the mvnw
# lines: both would silently change what that lane builds.
COPY .github/maven-ci-settings.xml .github/maven-ci-settings.xml
ARG UPSTREAM_PACKAGES_ACTOR
# The read token is a BuildKit SECRET (never an ARG/ENV, never in a layer or the image
# history). When it is not mounted the exported MAVEN_ARGS is simply not set here and
# whatever the environment already carries (the compose lane's ENV) is left alone.
# Resolve deps in a separate layer for cache friendliness.
RUN --mount=type=secret,id=packages_read_token \
    sh -euc '\
      if [ -f /run/secrets/packages_read_token ]; then \
        export UPSTREAM_PACKAGES_TOKEN="$(cat /run/secrets/packages_read_token)" MAVEN_ARGS="-s .github/maven-ci-settings.xml"; \
      fi; \
      ./mvnw -B dependency:go-offline'
COPY src src
RUN --mount=type=secret,id=packages_read_token \
    sh -euc '\
      if [ -f /run/secrets/packages_read_token ]; then \
        export UPSTREAM_PACKAGES_TOKEN="$(cat /run/secrets/packages_read_token)" MAVEN_ARGS="-s .github/maven-ci-settings.xml"; \
      fi; \
      ./mvnw -B package -DskipTests'

FROM eclipse-temurin:25-jre@sha256:fd4b1c02c64eef378212e23656fc0b0caa41a357876fa0b60e51ceda94a3db64
# curl is required by this image's docker-compose HEALTHCHECK (actuator/health/readiness);
# eclipse-temurin's jre base does not ship it, which silently breaks every
# `depends_on: condition: service_healthy` gate on a fresh compose boot.
RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build /work/target/*.jar app.jar
EXPOSE 8080
# `spring.application.name` defaults to hugmesh-be-gateway via
# application.yml (see src/main/resources/application.yml); override
# SPRING_APPLICATION_NAME at deploy time to spin up the same image as
# hugmesh-pki-gateway / hugmesh-fe-gateway, or per-brand
# ${BRAND}-{pki,be,fe}-gateway. (This repo's own compose.yaml runs the dev
# stack on that same hugmesh-be-gateway default.)
ENTRYPOINT ["java", "-jar", "/app/app.jar"]
