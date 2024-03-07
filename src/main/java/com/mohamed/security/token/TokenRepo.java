package com.mohamed.security.token;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;
import java.util.Optional;

public interface TokenRepo extends JpaRepository<Token, Long> {

    @Query(value = "SELECT t.* FROM token t INNER JOIN my_user_table u ON t.userid = u.id where u.id = :UserId and (t.expired = 0 or t.revoked = 0)",nativeQuery = true)
            List<Token>findAllValidTokensByUser(Long UserId);
    Optional<Token> findByToken(String token);
}
