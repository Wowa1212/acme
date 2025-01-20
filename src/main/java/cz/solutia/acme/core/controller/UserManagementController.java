package cz.solutia.acme.core.controller;

import cz.solutia.acme.core.model.User;
import jakarta.validation.Valid;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;

import java.util.UUID;

@Controller
public class UserManagementController {
    private static final Logger LOGGER = LogManager.getLogger(UserManagementController.class);

    @Value("${app.base-url}")
    private String baseUrl;

    private final JavaMailSender mailSender;

    @Autowired
    public UserManagementController(JavaMailSender mailSender) {
        this.mailSender = mailSender;
    }

    @GetMapping("/login")
    public String login() {
        return "login";
    }

    @GetMapping("/password-reset")
    public String passwordReset() {
        return "password-reset";
    }

    @PostMapping("/password-reset")
    public String passwordResetAction(@Valid @ModelAttribute User user, BindingResult result, Model model) {
        if (result.hasErrors()) {
            model.addAttribute("errors", result.getAllErrors());
            return "password-reset";
        }

        LOGGER.info("Sending password reset email to {}", user.getEmail());
        String token = UUID.randomUUID().toString();

        // Save the token associated with the user (this is just a placeholder, implement your own logic)
        // userService.savePasswordResetToken(user, token);

        try {
            if (user.getEmail() != null) {
                SimpleMailMessage message = new SimpleMailMessage();
                message.setTo(user.getEmail());
                message.setSubject("Password Reset");
                message.setText("To reset your password, please click the following link: " + baseUrl + "/reset-password/" + token);
                mailSender.send(message);
            }
        } catch (Exception e) {
            LOGGER.error("Unable to send the password reset email", e);
            model.addAttribute("error", "Unable to send the password reset email");
            return "password-reset";
        }

        return "redirect:/";
    }

    @GetMapping("/logout")
    public String logout() {
        return "redirect:/";
    }
}
