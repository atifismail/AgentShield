FROM eclipse-temurin:25-jdk AS build
WORKDIR /workspace

COPY gradlew gradlew.bat build.gradle settings.gradle ./
COPY gradle ./gradle
RUN ./gradlew --version

COPY src ./src
RUN ./gradlew clean bootJar --no-daemon -x test

FROM eclipse-temurin:25-jre AS runtime
WORKDIR /app

RUN useradd --system --uid 10001 agentshield
COPY --from=build /workspace/build/libs/*.jar app.jar
# Writable sandbox root for stdio MCP subprocesses (agentshield.stdio.sandbox-root default,
# design-stdio-sse-mcp-transport-and-sandboxing.md §5.3) — /app itself stays root-owned/read-only
# to this user otherwise; only this directory and the jar are writable/owned by the app user. In
# Kubernetes this path can be mounted as a separate volume independent of the read-only app root.
RUN mkdir -p mcp-sandboxes && chown agentshield:agentshield app.jar mcp-sandboxes
USER agentshield

EXPOSE 8080
ENTRYPOINT ["java", "-jar", "/app/app.jar"]
