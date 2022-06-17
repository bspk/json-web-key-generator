FROM maven:3.8.6-openjdk-11 AS builder
RUN mkdir ~/build
COPY . /build
WORKDIR /build
RUN mvn package
CMD ["java -jar ~/build/target/json-web-key-generator-0.9-SNAPSHOT-jar-with-dependencies.jar -t"]

FROM openjdk:11-jre-slim
COPY --from=0 /build/target/json-web-key-generator-0.9-SNAPSHOT-jar-with-dependencies.jar ./json-web-key-generator.jar
ENTRYPOINT ["java", "-jar", "json-web-key-generator.jar"]
