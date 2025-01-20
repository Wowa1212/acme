package cz.solutia.acme.core.service;

import cz.solutia.acme.core.model.AppUserDetails;
import cz.solutia.acme.core.model.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class AppUserDetailService implements UserDetailsService {
    private final UserService userService;

    public AppUserDetailService(UserService userService) {
        this.userService = userService;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Optional<User> userOptional = userService.findByUsername(username);
        if (userOptional.isEmpty()) {
            throw new UsernameNotFoundException(username);
        }

        User user = userOptional.get();
        return AppUserDetails.builder()
                .username(user.getUsername())
                .name(user.getFirstname() + " " + user.getLastname())
                .password(user.getPassword())
                .build();
    }
}
