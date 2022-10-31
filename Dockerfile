
# Get the builder image
FROM maven:3.8.6-openjdk-11 AS builder
COPY . /build
WORKDIR /build
# Build the app
# Artifact will be stored at /build/target/json-web-key-generator-0.9-SNAPSHOT-jar-with-dependencies.jar
RUN mvn package

# Build the image with the new .jar binary
# We need a jre 11+ starter container for this
FROM openjdk:11-jre-slim
ARG GIT_COMMIT=unspecified
ARG GIT_TAG=unspecified
LABEL org.opencontainers.image.authors="Besmir Zanaj"
LABEL org.opencontainers.image.revision=$GIT_COMMIT
LABEL org.opencontainers.image.version="$GIT_TAG"
COPY --from=0 /build/target/json-web-key-generator-0.9-SNAPSHOT-jar-with-dependencies.jar ./json-web-key-generator.jar
ENTRYPOINT ["java", "-jar", "json-web-key-generator.jar"]
