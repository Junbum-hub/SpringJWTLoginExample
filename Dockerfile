FROM openjdk:17-alpine

# JAR 파일을 이미지에 복사
COPY build/libs/*.jar /app.jar

# 애플리케이션이 사용할 포트를 노출
EXPOSE 8081

# ENTRYPOINT를 설정하여 특정 포트로 애플리케이션 실행
ENTRYPOINT ["java", "-jar", "/app.jar", "--server.port=8081"]
