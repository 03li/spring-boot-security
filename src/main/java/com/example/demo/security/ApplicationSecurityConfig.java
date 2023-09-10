package com.example.demo.security;

import static com.example.demo.security.Role.*;

import com.example.demo.auth.AppUserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter{
    private final AppUserService appUserService;
    private final PasswordEncoder passwordEncoder;

    @Autowired
    public ApplicationSecurityConfig(AppUserService appUserService, PasswordEncoder passwordEncoder) {
        this.appUserService = appUserService;
        this.passwordEncoder = passwordEncoder;
    }
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
            .formLogin()
	            .loginPage("/login").permitAll()
	            .defaultSuccessUrl("/courses",true)
                .passwordParameter("password")
                .usernameParameter("username")
	        .and()
	        .rememberMe()
                .rememberMeParameter("remember-me")
	        .and()
	        .logout()
	        	.logoutUrl("/logout")
	        	.clearAuthentication(true)
	        	.invalidateHttpSession(true)
	        	.deleteCookies("JSESSIONID","remember-me")
	        	.logoutSuccessUrl("/login");
    }

    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider(){
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setPasswordEncoder(passwordEncoder);
        provider.setUserDetailsService(appUserService);
        return provider;
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(daoAuthenticationProvider());
    }
}
