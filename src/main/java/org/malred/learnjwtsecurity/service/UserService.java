package org.malred.learnjwtsecurity.service;

import org.malred.learnjwtsecurity.domain.Role;
import org.malred.learnjwtsecurity.domain.User;

import java.util.List;

public interface UserService {
    User saveUser(User user);

    Role saveRole(Role role);

    void addRoleToUser(String username, String roleName);

    User getUser(String username);

    List<User> getUsers();
}
