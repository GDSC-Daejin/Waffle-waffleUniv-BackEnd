package gdg.waffle.BE.login.validation;

// 유효성 검사 그룹을 정의하는 클래스
public class ValidationGroups {
    public interface NotBlankGroup {}; // 필수 입력값 검증 그룹
    public interface PatternGroup {}; // 정규식 패턴 검증 그룹
}
