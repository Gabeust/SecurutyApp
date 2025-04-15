# Etapa de construcción
FROM azul/zulu-openjdk:23 AS build
WORKDIR /app

# Instalar Maven manualmente
RUN apt-get update && \
    apt-get install -y maven

COPY . .
RUN mvn clean package -DskipTests

# Etapa de ejecución
FROM azul/zulu-openjdk:23
WORKDIR /app
COPY --from=build /app/target/security-0.0.1-SNAPSHOT.jar app.jar
EXPOSE 8080
CMD ["java", "-jar", "app.jar"]
