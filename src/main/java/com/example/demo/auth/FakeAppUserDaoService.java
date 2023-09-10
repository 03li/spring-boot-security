package com.example.demo.auth;

import com.google.common.collect.Lists;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

import static com.example.demo.security.Role.*;
@Repository("fake")
public class FakeAppUserDaoService implements AppUserDao{
    private final PasswordEncoder passwordEncoder;
    public FakeAppUserDaoService(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }
    @Override
    public Optional<AppUser> selectAppUserByUsername(String username) {
        return getAppUsers().stream()
                .filter(u -> u.getUsername().equals(username))
                .findFirst();
    }
    private List<AppUser> getAppUsers(){
        List<AppUser> appUsers = Lists.newArrayList(
                new AppUser("a",
                        passwordEncoder.encode("p"),
                        STUDENT.getGrantedAuthorities(),
                        true,
                        true,
                        true,
                        true),
                new AppUser("l",
                        passwordEncoder.encode("p"),
                        ADMIN.getGrantedAuthorities(),
                        true,
                        true,
                        true,
                        true),
                new AppUser("t",
                        passwordEncoder.encode("p"),
                        ADMINTRAINEE.getGrantedAuthorities(),
                        true,
                        true,
                        true,
                        true)
        );
        return appUsers;
    }
}
