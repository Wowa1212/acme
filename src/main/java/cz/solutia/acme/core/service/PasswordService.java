package cz.solutia.acme.core.service;

import cz.solutia.acme.core.model.User;
import cz.solutia.acme.core.repository.UserRepository;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.passay.*;

import java.util.Arrays;

@Service
public class PasswordService {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder passwordEncoder;

    public PasswordService(UserRepository userRepository) {
        this.userRepository = userRepository;
        this.passwordEncoder = new BCryptPasswordEncoder();
    }

    /**
     * Validuje nové heslo na základě zadaných pravidel.
     * @param password Heslo k validaci.
     * @return true, pokud heslo splňuje všechna pravidla.
     */
    public boolean validatePassword(String password) {
        PasswordValidator validator = new PasswordValidator(Arrays.asList(
                new LengthRule(8, 32), // Délka hesla
                new CharacterRule(EnglishCharacterData.UpperCase, 1), // Velké písmeno
                new CharacterRule(EnglishCharacterData.LowerCase, 1), // Malé písmeno
                new CharacterRule(EnglishCharacterData.Digit, 1), // Číslice
                new CharacterRule(EnglishCharacterData.Special, 1), // Speciální znak
                new WhitespaceRule() // Žádné mezery
        ));

        RuleResult result = validator.validate(new PasswordData(password));
        if (!result.isValid()) {
            throw new IllegalArgumentException("Heslo nesplňuje bezpečnostní požadavky: " +
                    String.join(", ", validator.getMessages(result)));
        }
        return true;
    }

    /**
     * Změní heslo uživatele po validaci a šifrování.
     * @param username Uživatelské jméno.
     * @param newPassword Nové heslo.
     */
    public void changePassword(String username, String newPassword) {
        if (!validatePassword(newPassword)) {
            throw new IllegalArgumentException("Heslo nesplňuje bezpečnostní požadavky.");
        }

        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new IllegalArgumentException("Uživatel nenalezen."));

        String hashedPassword = passwordEncoder.encode(newPassword);
        user.setPassword(hashedPassword);
        userRepository.save(user);
    }
}
