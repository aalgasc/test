package com.computerspace.seguridad;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;


import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
@RequestMapping ("/")
public class SeguridadController {
	
	@GetMapping
	public String index (Model model) {
		
		
		return "index";
	}

	@GetMapping ("/marketing")
	public String marketing (Model model) {
		
		return "marketing";
	}

	@GetMapping ("/admin")
	public String administrador (Model model) {
		
		return "paneladmin";
	}
	
	@GetMapping ("/desarrollo")
	public String desarrollo (Model model) {
		
		return "desarrollo";
	}
	
	@GetMapping ("/403")
	public String error403 (Model model) {
		
		return "noautorizado";
	}
	@GetMapping ("/logout")
	public String logoutPage (HttpServletRequest request, HttpServletResponse response)
	{
		Authentication auth = SecurityContextHolder.getContext().getAuthentication();
		if (auth != null)
		{
			new SecurityContextLogoutHandler().logout(request, response, auth);
		}
		return "redirect:/";
	}
	@GetMapping ("/milogin")
	
	public String login (Model model) {
		
		return "milogin";
	}
}

