package cz.solutia.acme;

import cz.solutia.acme.core.model.User;
import cz.solutia.acme.core.repository.UserRepository;
import cz.solutia.acme.core.service.PasswordService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

class PasswordServiceTest {

    private PasswordService passwordService;
    private UserRepository userRepository;
    private BCryptPasswordEncoder passwordEncoder;

    @BeforeEach
    void setUp() {
        userRepository = Mockito.mock(UserRepository.class);
        passwordEncoder = new BCryptPasswordEncoder();
        passwordService = new PasswordService(userRepository);
    }

    @Test
    void validatePassword_ShouldPass_ForValidPassword() {
        String validPassword = "ValidPass1!";
        assertDoesNotThrow(() -> passwordService.validatePassword(validPassword));
    }

    @Test
    void validatePassword_ShouldFail_ForInvalidPassword() {
        String invalidPassword = "short";
        Exception exception = assertThrows(IllegalArgumentException.class, () -> passwordService.validatePassword(invalidPassword));
        assertTrue(exception.getMessage().contains("Heslo nesplňuje bezpečnostní požadavky"));
    }

    @Test
    void changePassword_ShouldChangePassword_ForValidInputs() {
        String username = "john.doe";
        String newPassword = "ValidPass1!";

        User user = new User();
        user.setUsername(username);
        user.setPassword(passwordEncoder.encode("OldPass1!"));

        when(userRepository.findByUsername(anyString())).thenReturn(Optional.of(user));
        when(userRepository.save(any(User.class))).thenReturn(user);

        assertDoesNotThrow(() -> passwordService.changePassword(username, newPassword));
        verify(userRepository, times(1)).save(user);

        assertTrue(passwordEncoder.matches(newPassword, user.getPassword()));
    }

    @Test
    void changePassword_ShouldThrowException_ForInvalidPassword() {
        String username = "john.doe";
        String invalidPassword = "short";

        User user = new User();
        user.setUsername(username);
        user.setPassword(passwordEncoder.encode("OldPass1!"));

        when(userRepository.findByUsername(anyString())).thenReturn(Optional.of(user));

        Exception exception = assertThrows(IllegalArgumentException.class, () -> passwordService.changePassword(username, invalidPassword));

        assertTrue(exception.getMessage().contains("Heslo nesplňuje bezpečnostní požadavky"));
        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    void changePassword_ShouldThrowException_WhenUserNotFound() {
        String username = "nonexistent.user";
        String newPassword = "ValidPass1!";

        when(userRepository.findByUsername(anyString())).thenReturn(Optional.empty());

        Exception exception = assertThrows(IllegalArgumentException.class, () -> passwordService.changePassword(username, newPassword));

        assertTrue(exception.getMessage().contains("Uživatel nenalezen"));
        verify(userRepository, never()).save(any(User.class));
    }
}

