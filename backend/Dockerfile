# Multi-stage build: compile with the JDK, run on the smaller JRE.
FROM eclipse-temurin:25-jdk AS build
WORKDIR /app

# Warm the wrapper/dependency layers before copying source for better caching.
COPY gradle ./gradle
COPY gradlew settings.gradle build.gradle ./
RUN ./gradlew --no-daemon --version

COPY src ./src
# Tests run in CI / locally (./gradlew test); the image build just packages.
RUN ./gradlew --no-daemon clean bootJar -x test

FROM eclipse-temurin:25-jre AS runtime
WORKDIR /app
COPY --from=build /app/build/libs/*.jar app.jar
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "/app/app.jar"]
