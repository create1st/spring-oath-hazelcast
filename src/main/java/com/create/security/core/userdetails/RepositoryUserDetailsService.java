/*
 * Copyright 2016 Sebastian Gil.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package com.create.security.core.userdetails;

import com.create.model.Person;
import com.create.repository.PersonRepository;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Repository;
import org.springframework.util.Assert;

import java.util.Arrays;
import java.util.Collection;

import static com.create.security.access.Roles.ROLE_ADMIN;
import static com.create.security.access.Roles.ROLE_USER;

/**
 * {@link Repository} based implementation of {@link UserDetailsService}.
 */
public class RepositoryUserDetailsService implements UserDetailsService {

    private final PersonRepository personRepository;

    /**
     * Creates new {@link RepositoryUserDetailsService}.
     *
     * @param personRepository must not be {@link null}.
     */
    public RepositoryUserDetailsService(final PersonRepository personRepository) {
        Assert.notNull(personRepository);
        this.personRepository = personRepository;
    }


    @Override
    public UserDetails loadUserByUsername(final String username) throws
            UsernameNotFoundException {
        final Person person = personRepository.findByLogin(username);

        if (person == null) {
            throw new UsernameNotFoundException(String.format("User does not exists : %s", username));
        }
        return new User(username, "password", getGrantedAuthorities(person));
    }

    private Collection<? extends GrantedAuthority> getGrantedAuthorities(final Person person) {
        final GrantedAuthority[] authorities = person.isPrivileged()
                ? new GrantedAuthority[]{() -> ROLE_ADMIN, () -> ROLE_USER}
                : new GrantedAuthority[]{() -> ROLE_USER};
        return Arrays.asList(authorities);
    }
}