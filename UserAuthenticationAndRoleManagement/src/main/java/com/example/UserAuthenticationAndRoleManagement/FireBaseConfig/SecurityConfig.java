package com.example.UserAuthenticationAndRoleManagement.FireBaseConfig;

import com.example.UserAuthenticationAndRoleManagement.auth.FirebaseAuthenticationService;
import com.example.UserAuthenticationAndRoleManagement.auth.FirebasePrincipal;
import com.google.firebase.auth.FirebaseAuthException;
import com.google.firebase.auth.FirebaseToken;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.WebUtils;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    private final FirebaseAuthenticationService authSvc;

    public SecurityConfig(FirebaseAuthenticationService authSvc){
        this.authSvc = authSvc;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED))
                .addFilterBefore(sessionCookieFilter(), UsernamePasswordAuthenticationFilter.class)
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/signup", "/login", "/api/auth/login", "/api/users","/login/json" , "send-welcome-message" , "send-welcome-message/json").permitAll()
                        .requestMatchers(HttpMethod.GET , "/api/admin/users/").permitAll()
                        .requestMatchers(HttpMethod.GET,"/api/notifications/guest/my-notifications").hasRole("GUEST")
                        .requestMatchers(HttpMethod.GET, "/api/users/by-firebase-uid").permitAll()
                        .requestMatchers(HttpMethod.GET, "/api/users/*/email").permitAll()
                        .requestMatchers(HttpMethod.GET, "/api/properties/**").permitAll()
                        .requestMatchers("/css/**", "/js/**", "/favicon.ico").permitAll()
                        .anyRequest().authenticated()
                )
                .logout(logout -> logout
                        .logoutUrl("/logout") // optional, defaults to /logout
                        .logoutSuccessUrl("/login?logout") // where to go after logout
                        .invalidateHttpSession(true)
                        .deleteCookies("SESSION", "REFRESH_TOKEN") // delete custom cookies if needed
                );

        return http.build();
    }


    // in SecurityConfig
    @Bean
    public AuthenticationManager authenticationManager() {
        return authentication -> {
            String firebaseUid = (String) authentication.getCredentials();
            FirebasePrincipal principal = authSvc.getPrincipalByUid(firebaseUid);
            return new UsernamePasswordAuthenticationToken(
                    principal,
                    null,
                    principal.getAuthorities()   // now contains ROLE_GUEST etc
            );
        };
    }

    @Bean
    public OncePerRequestFilter sessionCookieFilter() {
        return new OncePerRequestFilter() {
            @Override
            protected void doFilterInternal(
                    HttpServletRequest req,
                    HttpServletResponse res,
                    FilterChain chain
            ) throws ServletException, IOException {
                Cookie c = WebUtils.getCookie(req, "SESSION");
                if (c != null) {
                    // 1 verify the Firebase session cookie

                    try {
                        FirebaseToken token = authSvc.verifySession(c.getValue());

                        // 2 load your User + role from the DB
                        FirebasePrincipal principal =
                                authSvc.getPrincipalByUid(token.getUid());

                        // 3 build Spring Authentication with the real authorities
                        Authentication auth =
                                new org.springframework.security.authentication
                                        .UsernamePasswordAuthenticationToken(
                                        principal,
                                        null,
                                        principal.getAuthorities()
                                );

                        SecurityContextHolder
                                .getContext()
                                .setAuthentication(auth);
                    }catch (Exception e){

                    }
                }
                chain.doFilter(req, res);
            }
        };
    }


}

