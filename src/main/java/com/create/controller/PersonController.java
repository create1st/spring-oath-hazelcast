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

package com.create.controller;

import com.create.model.Person;
import com.create.repository.PersonRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

import static com.create.security.access.Roles.ROLE_ADMIN;

/**
 * REST {@link Controller} for {@link Person} data.
 */
@RestController
public class PersonController {

    @Autowired
    private PersonRepository personRepository;

    /**
     * Get all persons.
     *
     * @return List of {@link Person}s.
     */
    @PreAuthorize("hasRole('" + ROLE_ADMIN + "')")
    @RequestMapping(value = "/persons", method = RequestMethod.GET)
    public List<Person> getPersons() {
        return personRepository.findAll();
    }
}
