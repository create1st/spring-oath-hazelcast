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

package com.create.application.configuration;

import com.create.model.Person;
import com.create.repository.PersonRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.orm.jpa.EntityScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

import javax.annotation.PostConstruct;
import java.util.stream.Stream;

/**
 * JPA {@link Configuration}.
 */
@Configuration
@EntityScan({
        "com.create.model"
})
@EnableJpaRepositories({
        "com.create.repository"
})
@EnableAutoConfiguration
public class JpaConfiguration {

    @Autowired
    private PersonRepository personRepository;

    @PostConstruct
    public void initialize() {
        Stream.of("admin", "user")
                .map(login -> {
                    final Person user = new Person();
                    user.setLogin(login);
                    user.setPrivileged("admin".equals(login));
                    return user;
                })
                .forEach(personRepository::save);
    }
}
