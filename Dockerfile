FROM maven:3-jdk-14 AS builder

WORKDIR /build

COPY . .

RUN mvn package

FROM openjdk:14-jdk-alpine

COPY --from=builder /build/target/json-web-key-generator.jar /target/json-web-key-generator.jar

COPY json-web-key-generator.sh /json-web-key-generator.sh

ENTRYPOINT ["/json-web-key-generator.sh"]
