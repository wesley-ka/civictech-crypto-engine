# Stage 1: Build the application
FROM maven:3.9.6-eclipse-temurin-21-alpine AS builder
WORKDIR /app
COPY pom.xml .
RUN mvn dependency:go-offline -B
COPY src ./src
RUN mvn clean package -DskipTests -B

# Stage 2: Distribute lightweight runtime
FROM eclipse-temurin:21-jre-alpine
RUN apk add --no-cache tzdata
WORKDIR /app
COPY --from=builder /app/target/civictech-crypto-engine-1.0.0.jar app.jar

# Run as non-root user for security compliance
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
USER appuser

EXPOSE 8080
ENTRYPOINT ["java", "-XX:+UseG1GC", "-XX:MaxRAMPercentage=75.0", "-jar", "app.jar"]
