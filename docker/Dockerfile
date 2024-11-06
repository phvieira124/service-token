# Etapa 1: Build da aplicação Java
FROM maven:3.8.4-openjdk-17 AS build
WORKDIR /app
COPY . /app
RUN mvn clean package -DskipTests

# Etapa 2: Imagem final com Java e Mockoon CLI
FROM mockoon/cli:latest

# Instala o Java para executar o JAR
RUN apt-get update && apt-get install -y openjdk-17-jre-headless supervisor

# Configura o diretório de trabalho
WORKDIR /app

# Copia o JAR da aplicação gerado na Etapa 1
COPY --from=build /app/target/seu-app.jar /app/seu-app.jar

# Copia o arquivo de configuração do Mockoon
COPY mockoon-config.json /app/mockoon-config.json

# Configura o supervisor para iniciar ambos os serviços
COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf

# Expõe as portas necessárias
EXPOSE 8080 3000

# Comando para iniciar o supervisor
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]
