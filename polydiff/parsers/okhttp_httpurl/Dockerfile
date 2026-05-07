# Pinned for reproducibility against devcontainer/ JDK 21 line + OkHttp 4.12.x.
# Two-stage: download okhttp + okio jars in the build stage, run with both
# on the classpath in the runtime stage.

FROM eclipse-temurin:21.0.5_11-jdk AS build
WORKDIR /opt/parser

# OkHttp 4.12.0 + okio 3.6.0 (the okhttp 4.12.x line ships with okio 3.6.x).
# These are the public Maven Central artifacts.
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*
RUN curl -fsSL -o okhttp.jar  https://repo1.maven.org/maven2/com/squareup/okhttp3/okhttp/4.12.0/okhttp-4.12.0.jar \
 && curl -fsSL -o okio.jar    https://repo1.maven.org/maven2/com/squareup/okio/okio-jvm/3.6.0/okio-jvm-3.6.0.jar \
 && curl -fsSL -o kotlin.jar  https://repo1.maven.org/maven2/org/jetbrains/kotlin/kotlin-stdlib/1.9.10/kotlin-stdlib-1.9.10.jar
COPY Wrapper.java /opt/parser/Wrapper.java
RUN javac -cp 'okhttp.jar:okio.jar:kotlin.jar' Wrapper.java

FROM eclipse-temurin:21.0.5_11-jre
RUN groupadd --system parser && useradd --system --gid parser --uid 10001 parser
USER 10001:10001
WORKDIR /opt/parser
COPY --from=build --chown=10001:10001 /opt/parser/Wrapper.class /opt/parser/Wrapper.class
COPY --from=build --chown=10001:10001 /opt/parser/okhttp.jar    /opt/parser/okhttp.jar
COPY --from=build --chown=10001:10001 /opt/parser/okio.jar      /opt/parser/okio.jar
COPY --from=build --chown=10001:10001 /opt/parser/kotlin.jar    /opt/parser/kotlin.jar

ENTRYPOINT ["java", "-cp", "/opt/parser:/opt/parser/okhttp.jar:/opt/parser/okio.jar:/opt/parser/kotlin.jar", "Wrapper"]
