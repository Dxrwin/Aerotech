package com.Aerotech.demo.security

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.web.SecurityFilterChain

@Configuration
class SeguridadConfig {


    @Bean
    fun jwtUtil(): JwtUtil = JwtUtil()

    @Bean
    fun filterChain(http: HttpSecurity): SecurityFilterChain {
        http
            .authorizeHttpRequests { authz ->
                authz
                    .requestMatchers("/autenticacion/registrar", "/autenticacion/iniciar-sesion").permitAll()
                    .requestMatchers("/autenticacion/registrar", "/autenticacion/obtener-token").permitAll()
                    .requestMatchers("/admin/**").hasRole("ADMINISTRADOR")
                    .requestMatchers("/empleado/**").hasRole("EMPLEADO")
                    .requestMatchers("/cliente/**").hasRole("CLIENTE")
                    .anyRequest().authenticated()
            }
            .csrf { it.disable() }
            .httpBasic { it.disable() }
        return http.build()
    }

}