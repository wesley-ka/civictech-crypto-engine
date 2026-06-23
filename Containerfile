# Stage 1: Build the application
FROM docker.io/maven:3.9.6-eclipse-temurin-21-alpine AS builder
WORKDIR /app
COPY pom.xml .
RUN mvn dependency:go-offline -B
COPY src ./src
RUN mvn clean package -DskipTests -B

# Stage 2: Distribute lightweight runtime
FROM docker.io/eclipse-temurin:21-jre-alpine
RUN apk add --no-cache tzdata
WORKDIR /app
COPY --from=builder /app/target/civictech-crypto-engine-1.0.0.jar app.jar

RUN addgroup -S appgroup && adduser -S appuser -G appgroup \
    && mkdir -p /app/local-storage \
    && chown -R appuser:appgroup /app/local-storage
USER appuser

ENTRYPOINT ["java", \
  "-XX:+UseG1GC", \
  "-XX:MaxRAMPercentage=75.0", \
  "-Djava.security.egd=file:/dev/./urandom", \
  "-jar", "app.jar"]
