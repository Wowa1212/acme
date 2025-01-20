package cz.solutia.acme.core.controller;

import cz.solutia.acme.core.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ModelAttribute;

import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.Locale;

@ControllerAdvice
public class AcmeControllerAdvice {
    @Autowired
    private UserRepository userRepository;

    @Autowired
    private MessageSource messageSource;

    @Value("${app.version}")
    private String appVersion;

    @ModelAttribute("formattedDate")
    public String getFormattedDate() {
        Locale locale = LocaleContextHolder.getLocale();
        LocalDate today = LocalDate.now();
        DateTimeFormatter dateFormatter;

        if (locale.equals(new Locale("cs"))) {
            dateFormatter = DateTimeFormatter.ofPattern("d. MMMM yyyy", locale);
        } else {
            dateFormatter = DateTimeFormatter.ofPattern("d MMMM yyyy", locale);
        }

        return today.format(dateFormatter);
    }

    @ModelAttribute("appVersion")
    public String getAppVersion() {
        return appVersion;
    }
}