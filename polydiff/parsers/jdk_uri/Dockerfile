# Pinned for reproducibility against devcontainer/ JDK 21 line.
# Multi-stage build: compile in eclipse-temurin:21-jdk, run in :21-jre.
FROM eclipse-temurin:21.0.5_11-jdk AS build
WORKDIR /opt/parser
COPY Wrapper.java /opt/parser/Wrapper.java
RUN javac Wrapper.java

FROM eclipse-temurin:21.0.5_11-jre
RUN groupadd --system parser && useradd --system --gid parser --uid 10001 parser
USER 10001:10001
WORKDIR /opt/parser
COPY --from=build --chown=10001:10001 /opt/parser/Wrapper.class /opt/parser/Wrapper.class
ENTRYPOINT ["java", "-cp", "/opt/parser", "Wrapper"]
