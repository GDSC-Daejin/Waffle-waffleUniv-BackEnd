작성한 Swagger 확인하기

1. 스프링 프로젝트 실행
2. 브라우저에서 localhost:8080/swagger-ui/index.html 입력


JPA, mySQL 활성화하기 

데이터베이스 세팅 없이도 우선 프로젝트를 실행할 수 있도록 해당 디펜던시 주석처리 해두었습니다.
build.gradle 들어가서 아래의 주석을 해제해주시고 src/main/resources 속의 application.properties 에서 DB 설정 완료해주시면 정상적으로 작동됩니다!

//	implementation 'org.springframework.boot:spring-boot-starter-data-jpa'
//	runtimeOnly 'com.mysql:mysql-connector-j'
