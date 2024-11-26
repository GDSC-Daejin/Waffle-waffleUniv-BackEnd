package gdg.waffle.BE.comment.repository;

import gdg.waffle.BE.comment.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<User, Integer> {
}
