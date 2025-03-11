package gdg.waffle.BE.common.exception;

import jakarta.persistence.EntityNotFoundException;
import lombok.AllArgsConstructor;
import lombok.Data;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.server.ResponseStatusException;

// 전역 예외 처리 클래스: 애플리케이션에서 발생하는 예외를 한 곳에서 처리하여 공통된 응답 형식 제공
@RestControllerAdvice
public class GlobalExceptionHandler {

    // 잘못된 요청 (400 Bad Request)
    @ExceptionHandler({IllegalArgumentException.class})
    public ResponseEntity<String> handleBadRequest(IllegalArgumentException e) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(e.getMessage());
    }

    // 유효성 검사 실패 (400 Bad Request) - @Valid, @Validated 사용 시 발생
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<String> handleValidationException(MethodArgumentNotValidException e) {
        String errorMessage = e.getBindingResult().getAllErrors().get(0).getDefaultMessage();
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorMessage);
    }

    // 인증 실패 (401 Unauthorized) - 로그인하지 않은 사용자가 인증이 필요한 API 호출 시 발생
    @ExceptionHandler(ResponseStatusException.class)
    public ResponseEntity<String> handleUnauthorizedException(ResponseStatusException e) {
        return ResponseEntity.status(e.getStatusCode()).body(e.getReason());
    }

    // 데이터 없음 (404 Not Found) - 요청한 리소스를 찾을 수 없는 경우
    @ExceptionHandler(EntityNotFoundException.class)
    public ResponseEntity<String> handleEntityNotFound(EntityNotFoundException e) {
        return ResponseEntity.status(HttpStatus.NOT_FOUND)
                .body(e.getMessage());
    }

    // 접근 권한 없음 (403 Forbidden) - 권한이 없는 사용자가 요청 시 발생
    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<String> handleAccessDenied(AccessDeniedException e) {
        return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .body("접근 권한이 없습니다.");
    }

    // 서버 내부 오류 (500 Internal Server Error) - 예상치 못한 예외 발생 시 처리
    @ExceptionHandler(Exception.class)
    public ResponseEntity<String> handleAllExceptions(Exception e) {
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body("서버 오류 발생: " + e.getMessage());
    }

    // NullPointerException
    @ExceptionHandler(NullPointerException.class)
    public ResponseEntity<String> handleNullPointerException(NullPointerException e){
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(e.getMessage());
    }

    // 공통 응답 DTO
    @Data
    @AllArgsConstructor
    static class ErrorResponse {
        private String message; // 에러 메시지
        private int status; // HTTP 상태 코드
    }
}