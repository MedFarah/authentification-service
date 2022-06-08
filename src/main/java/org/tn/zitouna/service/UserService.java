package org.tn.zitouna.service;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.tn.zitouna.dao.AppUserRepository;
import org.tn.zitouna.entities.AppUser;

@Service
public class UserService  implements UserDetailsService {

	private AppUserRepository appUserRepository;
	@Autowired
	public UserService(AppUserRepository appUserRepository) {
		this.appUserRepository = appUserRepository;
	}

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		// TODO Auto-generated method stub
		AppUser user=appUserRepository.findByUsername(username);
        if(user==null) throw new UsernameNotFoundException("invalid user");
        Collection<GrantedAuthority> authorities=new ArrayList<>();
        
            authorities.add(new SimpleGrantedAuthority(user.getRoles()));
     
        return new User(user.getUsername(), user.getPassword(), authorities);
	}
	
	public AppUser register(AppUser u) {
		//String p = new String(new BCryptPasswordEncoder().encode(u.getPassword()));
		//u.setPassword(p);
		u.setRoles("admin");u.setActived(true);
		return appUserRepository.insert(u);
	}
	
	public AppUser findUserByUserName(String username) {
		return appUserRepository.findByUsername(username);
	}

	public List<AppUser> getAllUsers(){
		return appUserRepository.findAll();
	}
	
	public AppUser updateUser(AppUser u) {
		return appUserRepository.save(u);
	}
	
	public void supprimerUser( String id) {
		appUserRepository.deleteById(id);
	}
}
