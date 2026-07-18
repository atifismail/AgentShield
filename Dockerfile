FROM eclipse-temurin:21-jdk AS build
WORKDIR /workspace

COPY gradlew gradlew.bat build.gradle settings.gradle ./
COPY gradle ./gradle
RUN ./gradlew --version

COPY src ./src
RUN ./gradlew clean bootJar --no-daemon -x test

FROM eclipse-temurin:21-jre AS runtime
WORKDIR /app

RUN useradd --system --uid 10001 agentshield
COPY --from=build /workspace/build/libs/*.jar app.jar
RUN chown agentshield:agentshield app.jar
USER agentshield

EXPOSE 8080
ENTRYPOINT ["java", "-jar", "/app/app.jar"]
