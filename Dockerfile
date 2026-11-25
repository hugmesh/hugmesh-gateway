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

# ---- Java4Shell (CVE-2026-114938): patched Java 25 runtime ------------------------------
# 25.0.5.1 fixes the heap overflow in the Base64 AVX-512 intrinsic, but eclipse-temurin:25-jre
# on Docker Hub still ships the vulnerable 25.0.5+8. Adoptium built Temurin 25.0.5.1+2 for
# linux x64 only, so arm64 gets a JRE linked (jlink, same module set as the base JRE) from
# Amazon Corretto 25.0.5.1.2, the same 25.0.5.1 security release. Both downloads are pinned to
# the vendors' published sha256. The runtime stage swaps this JRE in only while its base JRE
# is older. Remove this stage and the swap once eclipse-temurin:25-jre itself is >= 25.0.5.1.
FROM eclipse-temurin:25-jre@sha256:fd4b1c02c64eef378212e23656fc0b0caa41a357876fa0b60e51ceda94a3db64 AS jre-cve-2026-114938
ARG JRE_X64_URL=https://github.com/adoptium/temurin25-binaries/releases/download/jdk-25.0.5.1%2B2/OpenJDK25U-jre_x64_linux_hotspot_25.0.5.1_2.tar.gz
ARG JRE_X64_SHA256=2edef9e4f81ec5ee426d023336d4cfbd7b4644e99884e7a73a6a867b70b17acf
ARG JDK_AARCH64_URL=https://corretto.aws/downloads/resources/25.0.5.1.2/amazon-corretto-25.0.5.1.2-linux-aarch64.tar.gz
ARG JDK_AARCH64_SHA256=9370d3e5bcf0d165e6be4a78c3f6b57160af16d3033319af583800251eb91df2
RUN set -eu; \
    mkdir -p /opt/jre; \
    arch="$(dpkg --print-architecture)"; \
    case "${arch}" in \
      amd64) url="${JRE_X64_URL}"; sum="${JRE_X64_SHA256}" ;; \
      arm64) url="${JDK_AARCH64_URL}"; sum="${JDK_AARCH64_SHA256}" ;; \
      *) echo "jre-cve-2026-114938: no patched build for ${arch}; keeping the base JRE"; exit 0 ;; \
    esac; \
    apt-get update; \
    apt-get install -y --no-install-recommends curl ca-certificates; \
    rm -rf /var/lib/apt/lists/*; \
    curl -fsSL --retry 3 -o /tmp/java.tar.gz "${url}"; \
    printf '%s  /tmp/java.tar.gz\n' "${sum}" > /tmp/java.sha256; \
    sha256sum -c /tmp/java.sha256; \
    mkdir /tmp/java; \
    tar -xzf /tmp/java.tar.gz -C /tmp/java --strip-components=1; \
    rmdir /opt/jre; \
    if [ "${arch}" = amd64 ]; then \
      mv /tmp/java /opt/jre; \
    else \
      java --list-modules > /tmp/modules; \
      modules="$(sed 's/@.*//' /tmp/modules | paste -sd, -)"; \
      [ -n "${modules}" ]; \
      /tmp/java/bin/jlink --add-modules "${modules}" --no-man-pages --no-header-files --output /opt/jre; \
      rm -rf /tmp/java /tmp/modules; \
    fi; \
    rm -f /tmp/java.tar.gz /tmp/java.sha256; \
    /opt/jre/bin/java -version

FROM eclipse-temurin:25-jre@sha256:fd4b1c02c64eef378212e23656fc0b0caa41a357876fa0b60e51ceda94a3db64
# Java4Shell (CVE-2026-114938): use the patched JRE from the stage above while the base JRE
# is older than 25.0.5.1 (a symlink, so the JRE is not copied a second time).
COPY --from=jre-cve-2026-114938 /opt/jre/ /opt/java/jre-25.0.5.1/
RUN base="$(sed -n 's/^JAVA_VERSION="\(.*\)"$/\1/p' /opt/java/openjdk/release)" \
    && printf '%s\n25.0.5.1\n' "${base}" > /tmp/jre-versions \
    && if [ -x /opt/java/jre-25.0.5.1/bin/java ] && [ "${base}" != 25.0.5.1 ] \
          && sort -V -C /tmp/jre-versions; then \
         rm -rf /opt/java/openjdk && ln -s jre-25.0.5.1 /opt/java/openjdk && ldconfig; \
       else \
         rm -rf /opt/java/jre-25.0.5.1; \
       fi \
    && rm -f /tmp/jre-versions \
    && java -version
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
