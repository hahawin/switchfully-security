package com.cegeka.switchfully.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;

@Configuration
@EnableWebSecurity
//annotation needed for spring to pick up the @PreAuthorize annotations on the ArmyResource
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private AuthenticationEntryPoint authEntryPoint;
    @Autowired
    private ArmyAuthenticationProvider authenticationProvider;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable()
                //One way to fix the authorisation problem is using the 'antmatchers' methods to force users to have certain role(s) if they want to access a certain endpoint
                //advantage: able to secure multiple, similar url's at the same time
                //disadvantage: this code is completely decoupled from the Rest-controller code. This makes it easy to forget to adjust it when e.g. adding a new rest-call
//               .authorizeRequests() 
//                .antMatchers("/armies").hasRole("CIVILIAN")
//                .antMatchers("/armies/promote/**").hasRole("HUMAN_RELATIONSHIPS")
//                .antMatchers("/armies/discharge/**").hasRole("HUMAN_RELATIONSHIPS")
//                .antMatchers("/armies/nuke").hasRole("GENERAL")
//                .antMatchers("/armies/**").hasAnyRole("PRIVATE", "GENERAL")
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and().httpBasic()
                .authenticationEntryPoint(authEntryPoint);
    }

    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        PasswordEncoder encoder =
                PasswordEncoderFactories.createDelegatingPasswordEncoder();

        auth.authenticationProvider(authenticationProvider);
    }

}
