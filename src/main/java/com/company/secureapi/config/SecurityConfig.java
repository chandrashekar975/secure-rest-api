package com.company.secureapi.config;

import com.company.secureapi.security.CustomAccessDeniedHandler;
import com.company.secureapi.security.CustomAuthenticationEntryPoint;
import com.company.secureapi.security.jwt.JwtAuthenticationFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import com.company.secureapi.security.RateLimitingFilter;
import com.company.secureapi.audit.ApiLoggingFilter;
import com.company.secureapi.audit.ApiLogRepository;


@Configuration
@EnableMethodSecurity
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final CustomAuthenticationEntryPoint authenticationEntryPoint;
    private final CustomAccessDeniedHandler accessDeniedHandler;
    private final RateLimitingFilter rateLimitingFilter;
    private final ApiLogRepository apiLogRepository;

    public SecurityConfig(JwtAuthenticationFilter jwtAuthenticationFilter,
                          CustomAuthenticationEntryPoint authenticationEntryPoint,
                          CustomAccessDeniedHandler accessDeniedHandler,
                          RateLimitingFilter rateLimitingFilter,
                          ApiLogRepository apiLogRepository) {
        this.jwtAuthenticationFilter = jwtAuthenticationFilter;
        this.authenticationEntryPoint = authenticationEntryPoint;
        this.accessDeniedHandler = accessDeniedHandler;
        this.rateLimitingFilter = rateLimitingFilter;
        this.apiLogRepository = apiLogRepository;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        http
                .csrf(csrf -> csrf.disable())
                .headers(headers -> headers
                        .frameOptions(frame -> frame.deny())
                        .xssProtection(xss -> xss.disable())
                )
                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                ).exceptionHandling(exception ->
                        exception
                                .authenticationEntryPoint(authenticationEntryPoint)
                                .accessDeniedHandler(accessDeniedHandler)
                )
                .authorizeHttpRequests(auth ->
                        auth
                                // Public: static resources
                                .requestMatchers(
                                        "/", "/index.html", "/dashboard.html",
                                        "/*.html", "/*.css", "/*.js",
                                        "/css/**", "/js/**", "/images/**",
                                        "/favicon.ico"
                                ).permitAll()
                                // Public: auth endpoints
                                .requestMatchers("/api/v1/auth/**").permitAll()
                                // ADMIN only
                                .requestMatchers("/api/v1/admin/**").hasRole("ADMIN")
                                // AUDITOR only
                                .requestMatchers("/api/v1/logs/**").hasRole("AUDITOR")
                                // Everything else requires authentication
                                .anyRequest().authenticated()
                )
                .addFilterBefore(rateLimitingFilter,
                        UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(jwtAuthenticationFilter,
                        UsernamePasswordAuthenticationFilter.class)
                .addFilterAfter(new ApiLoggingFilter(apiLogRepository),
                        UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public AuthenticationManager authenticationManager(
            AuthenticationConfiguration configuration
    ) throws Exception {
        return configuration.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }
}