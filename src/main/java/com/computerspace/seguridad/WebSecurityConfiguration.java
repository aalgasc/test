package com.computerspace.seguridad;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;


@EnableWebSecurity
public class WebSecurityConfiguration  extends WebSecurityConfigurerAdapter{
	@Autowired
	private AccessDeniedHandler accessDeniedHandler;
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.csrf().disable()
		.authorizeRequests()
		.antMatchers("/" , "/logout" , "/403").permitAll()
		.antMatchers("/marketing").hasAnyRole("MARKETING")
		.antMatchers("/desarrollo").hasAnyRole("DESARROLLO")
		.antMatchers("/admin").hasAnyRole("ADMINISTRADOR")
		.anyRequest().authenticated()
		.and()
		.formLogin()
		.loginPage("/milogin").usernameParameter("usuario").passwordParameter("contrasena")
		//.loginPage("/login")
		.permitAll()
		.and()
		.logout()
		.permitAll().logoutRequestMatcher(new AntPathRequestMatcher("/logout")).logoutSuccessUrl("/")
		.and()
		.exceptionHandling().accessDeniedHandler(accessDeniedHandler);
		
		
		
	
	}
	
	@Autowired
	public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
		
		BCryptPasswordEncoder encoder = passwordEncoder ();
		auth.inMemoryAuthentication()
		.withUser("pesetero").password(encoder.encode("1234")).roles("MARKETING")
		.and()
		.withUser("desarrollador").password(encoder.encode("1111")).roles("DESARROLLO")
		.and()
		.withUser("admin").password(encoder.encode("2222")).roles("ADMINISTRADOR");
		
	}
	
	@Bean
	public BCryptPasswordEncoder passwordEncoder () {
		return new BCryptPasswordEncoder();
	}
	
	
}
