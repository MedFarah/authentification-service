package org.tn.zitouna.web;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.tn.zitouna.configuration.JWTTokenUtil;
import org.tn.zitouna.configuration.UserPrincipal;
import org.tn.zitouna.entities.AppUser;
import org.tn.zitouna.service.UserService;

@RestController
//@CrossOrigin(origins = "http://localhost:4200")
public class UserController {

	private UserService userService;
	private JWTTokenUtil jwtTokenUtil;
	private AuthenticationManager authenticationManager;
	


	@Autowired
	public UserController(UserService userService, JWTTokenUtil jwtTokenUtil,
			AuthenticationManager authenticationManager) {
		this.userService = userService;
		this.jwtTokenUtil = jwtTokenUtil;
		this.authenticationManager = authenticationManager;
	}

	@PostMapping("/register")
	public AppUser register(@RequestBody AppUser user) {
		
		user.setActived(true);
		return userService.register(user);
	}

	@PostMapping(path = "/login")
	public ResponseEntity<AppUser> login(@RequestBody AppUser userr) {
		this.authenticate(userr.getUsername(), userr.getPassword());

		AppUser user = userService.findUserByUserName(userr.getUsername());
		user.setPassword(null);
		String jwtToken = this.jwtTokenUtil.generateToken(new UserPrincipal(user));

		HttpHeaders headers = new HttpHeaders();
		headers.add("Authorization", "Bearer " + jwtToken);

		return ResponseEntity.ok().headers(headers).body(user);

	}

	private void authenticate(String userName, String password) {

		authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(userName, password));

	}
	
	@GetMapping("/users")
	public List<AppUser> getAllUsers(){
		return userService.getAllUsers();
	}
	
	@DeleteMapping("/users/{id}")
	public void deleteUser(@PathVariable String id){
		 userService.supprimerUser(id);
	}
	
	@PutMapping("/users")
	public AppUser updateUser(@RequestBody AppUser u) {
		return userService.updateUser(u);
	}
	/*
	 * @RequestMapping(value="/getLoggedUser") public User getLoggedUser
	 * (HttpServletRequest httpServletRequest){
	 * 
	 * // String requestToken = httpServletRequest.getHeader("Authorization");
	 * 
	 * String userName = null; String jwtToken = null;
	 * 
	 * jwtToken = requestToken.substring(7); userName =
	 * this.jwtTokenUtil.getUserNameFromToken(jwtToken); return
	 * userService.findUserByUserName(userName); }
	 */

}
