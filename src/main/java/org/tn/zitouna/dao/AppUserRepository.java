package org.tn.zitouna.dao;

import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;
import org.tn.zitouna.entities.AppUser;

@Repository
public interface AppUserRepository extends MongoRepository<AppUser, String> {

	public AppUser findByUsername(String username);
}
