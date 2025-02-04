package cz.solutia.acme.config;

import com.transferwise.icu.ICUMessageSource;
import com.transferwise.icu.ICUReloadableResourceBundleMessageSource;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.LocaleResolver;
import org.springframework.web.servlet.i18n.CookieLocaleResolver;
import org.springframework.web.servlet.i18n.LocaleChangeInterceptor;

import java.util.Locale;
import java.util.TimeZone;

@Configuration
public class MyBeansConfig {
    @Bean
    public LocaleResolver localeResolver() {
        CookieLocaleResolver localeResolver = new CookieLocaleResolver();
        localeResolver.setDefaultLocale(Locale.ENGLISH);
        localeResolver.setDefaultTimeZone(TimeZone.getTimeZone("UTC"));
        return localeResolver;
    }

    @Bean
    public LocaleChangeInterceptor localeChangeInterceptor() {
        LocaleChangeInterceptor localeChangeInterceptor = new LocaleChangeInterceptor();
        localeChangeInterceptor.setParamName("locale");  // Changing the locale using the "locale" parameter
        return localeChangeInterceptor;
    }

    @Bean
    public ICUMessageSource messageSource() {
        ICUReloadableResourceBundleMessageSource messageSource = new ICUReloadableResourceBundleMessageSource();
        messageSource.setBasename("classpath:lang/messages");
        messageSource.setDefaultEncoding("UTF-8");
        return messageSource;
    }
}
