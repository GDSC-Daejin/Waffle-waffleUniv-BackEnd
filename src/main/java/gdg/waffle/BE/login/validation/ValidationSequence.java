package gdg.waffle.BE.login.validation;
import jakarta.validation.GroupSequence;

@GroupSequence({ValidationGroups.NotBlankGroup.class, ValidationGroups.PatternGroup.class})
public interface ValidationSequence {
}