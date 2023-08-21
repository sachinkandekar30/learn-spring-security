package com.example.learnspringsecurity.basicauth;


import org.springframework.boot.autoconfigure.jdbc.EmbeddedDataSourceConfiguration;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabase;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.security.config.annotation.SecurityConfigurer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.SecurityContextConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.servlet.util.matcher.MvcRequestMatcher;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.web.servlet.handler.HandlerMappingIntrospector;

import javax.sql.DataSource;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableMethodSecurity(jsr250Enabled = true,securedEnabled = true)
public class BasicAuthSecurityConfiguration {

    //this is added https://github.com/jzheaux/cve-2023-34035-mitigations
    //https://spring.io/security/cve-2023-34035
    @Bean
    MvcRequestMatcher.Builder mvc(HandlerMappingIntrospector introspector) {
        return new MvcRequestMatcher.Builder(introspector);
    }

    //WE are going to disable CSRF token that is must require for POST,Put.. request by default in spring security.
    //WE want ro build the stateless APIs
    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http, MvcRequestMatcher.Builder mvc) throws Exception {
        http.authorizeHttpRequests((requests) ->
                requests.requestMatchers(mvc.pattern("/users")).hasRole("USER")
                .requestMatchers(mvc.pattern("/admin/**")).hasRole("ADMIN")
                        .anyRequest().authenticated());
        //Disabling session for making web APIs Stateless
        http.sessionManagement( session->
                session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
       // http.formLogin(withDefaults()); //we are default disabling form based login
        http.httpBasic(withDefaults());
        http.csrf(csrf -> csrf.disable());

        http.headers(heades -> heades.frameOptions(frameoption -> frameoption.sameOrigin()));

        return http.build();


    }

    //This are the global configuration for cors origine
    @Bean
    public WebMvcConfigurer crosConfiguration() {
        return new WebMvcConfigurer(){
            public void addCrossMapping(CorsRegistry corsRegistry){
                corsRegistry.addMapping("/**")
                        .allowedMethods("*")
                        .allowedOrigins("http://localhost:3000");
            }
        };
    }




    //This is in memory user details manager
//    @Bean
//    public UserDetailsService userDetails(){
//
//       var user = User.builder().username("user")
//                .password("{noop}password")
//                .roles("USER")
//                .build();
//
//        var admin = User.builder().username("admin")
//                .password("{noop}password")
//                .roles("ADMIN")
//                .build();
//
//        return new InMemoryUserDetailsManager(user,admin);
//    }

    //Configure the userSource

    @Bean
    public DataSource dataSource(){
        return new EmbeddedDatabaseBuilder().setType(EmbeddedDatabaseType.H2)
                .addScript(JdbcDaoImpl.DEFAULT_USER_SCHEMA_DDL_LOCATION)
                .build();
    }


    @Bean
    public UserDetailsService userDetails(DataSource dataSource){

        var user = User.builder().username("user")
                //.password("{noop}password")
                .password("password")
                .passwordEncoder(str -> passwordEncoder().encode(str))
                .roles("USER")
                .build();

        var admin = User.builder().username("admin")
                //.password("{noop}password")
                .password("password")
                .passwordEncoder(str -> passwordEncoder().encode(str))
                .roles("ADMIN")
                .build();
       var jdbcUserDetailsManager = new JdbcUserDetailsManager(dataSource);
        jdbcUserDetailsManager.createUser(user);
        jdbcUserDetailsManager.createUser(admin);

        return jdbcUserDetailsManager;
    }
    @Bean
    public BCryptPasswordEncoder passwordEncoder(){
      return   new BCryptPasswordEncoder();
    }
}
