package cz.solutia.acme.core.controller;

import cz.solutia.acme.core.model.User;
import cz.solutia.acme.core.repository.UserRepository;
import cz.solutia.acme.core.service.PasswordService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.Optional;

@Controller
public class SettingsController {
    private final UserRepository userRepository;
    private final PasswordService passwordService;

    @Autowired
    public SettingsController(UserRepository userRepository, PasswordService passwordService) {
        this.userRepository = userRepository;
        this.passwordService = passwordService;
    }

    @GetMapping("/settings")
    public String settings(Model model) {
        model.addAttribute("menu", "settings");

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        String firstname = "";
        String lastname = "";
        String email = authentication.getName();
        Optional<User> user = userRepository.findByUsername(authentication.getName());
        if (user.isPresent()) {
            firstname = user.get().getFirstname();
            lastname = user.get().getLastname();
        }

        model.addAttribute("firstname", firstname);
        model.addAttribute("lastname", lastname);
        model.addAttribute("email", email);
        return "settings";
    }

    /**
     * Zpracování požadavku na změnu hesla.
     */
    @PostMapping("/settings/change-password")
    public String changePassword(@RequestParam String newPassword,
                                 @RequestParam String confirmPassword,
                                 Model model) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String username = authentication.getName();

        if (!newPassword.equals(confirmPassword)) {
            model.addAttribute("error", "Zadaná hesla se neshodují.");
            return "settings";
        }

        try {
            passwordService.changePassword(username, newPassword);
            model.addAttribute("message", "Heslo bylo úspěšně změněno.");
        } catch (IllegalArgumentException e) {
            model.addAttribute("error", e.getMessage());
        }
        return "settings";
    }
}
