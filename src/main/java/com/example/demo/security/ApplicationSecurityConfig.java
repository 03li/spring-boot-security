package com.example.demo.security;

import static com.example.demo.security.Permission.*;
import static com.example.demo.security.Role.*;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter{

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .csrf().disable()
            .authorizeRequests()
            .antMatchers("/","/index","/favicon.ico").permitAll()
            .antMatchers("/api/**").hasRole(STUDENT.name())
//            .antMatchers(HttpMethod.DELETE,"/management/**").hasAuthority(COURSE_WRITE.getPermission())
//            .antMatchers(HttpMethod.PUT,"/management/**").hasAuthority(COURSE_WRITE.getPermission())
//            .antMatchers(HttpMethod.POST,"/management/**").hasAuthority(COURSE_WRITE.getPermission())
//            .antMatchers(HttpMethod.GET,"/management/**").hasAnyRole(ADMIN.name(),ADMINTRAINEE.name())
            .anyRequest().authenticated()
            .and()
            .httpBasic();
    }

    @Override
    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails annsSmithUser = User.builder()
            .username("a")
            .password(passwordEncoder().encode("p"))
            // .roles(STUDENT.name())
            .authorities(STUDENT.getGrantedAuthorities())
            .build();

        UserDetails linda = User.builder()
            .username("l")
            .password(passwordEncoder().encode("p"))
            // .roles(ADMIN.name())
            .authorities(ADMIN.getGrantedAuthorities())
            .build();

        UserDetails tom = User.builder()
            .username("t")
            .password(passwordEncoder().encode("p"))
            // .roles(ADMINTRAINEE.name())
            .authorities(ADMINTRAINEE.getGrantedAuthorities())
            .build();

        return new InMemoryUserDetailsManager(
            annsSmithUser, linda, tom
        );
    }


    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder(10);
    }
    
}
