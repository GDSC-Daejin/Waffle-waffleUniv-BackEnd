package gdg.waffle.BE.login.validation;
import jakarta.validation.GroupSequence;

// 유효성 검사 그룹의 실행 순서를 정의하는 인터페이스
@GroupSequence({ValidationGroups.NotBlankGroup.class, ValidationGroups.PatternGroup.class})
public interface ValidationSequence {
}