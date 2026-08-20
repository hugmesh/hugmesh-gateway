# HugMesh Gateway — multi-stage build.
#
# Stage 1: build the fat jar with Maven on a JDK image.
# Stage 2: copy the jar onto a slim JRE base so the runtime image
# stays under ~200 MB.

FROM eclipse-temurin:25-jdk AS build
WORKDIR /work
COPY mvnw mvnw.cmd ./
COPY .mvn .mvn
COPY pom.xml ./
# Resolve deps in a separate layer for cache friendliness.
RUN ./mvnw -B dependency:go-offline
COPY src src
RUN ./mvnw -B package -DskipTests

FROM eclipse-temurin:25-jre
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
