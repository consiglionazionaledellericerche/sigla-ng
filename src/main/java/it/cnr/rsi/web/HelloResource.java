package it.cnr.rsi.web;

import it.cnr.rsi.domain.Hello;
import it.cnr.rsi.repository.HelloRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.security.access.annotation.Secured;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

import static java.util.stream.Collectors.toList;

/**
 * Created by francesco on 07/03/17.
 */

@RestController
public class HelloResource {

    private static final Logger LOGGER = LoggerFactory.getLogger(HelloResource.class);

    public static final String API_HELLO = "/api/hello";

    @Autowired
    private HelloRepository helloRepository;

    @GetMapping(API_HELLO)
    public List<String> hello(){
        return helloRepository
                .findAll()
                .stream()
                .map(Hello::getName)
                .collect(toList());
    }

    @Secured("admin")
    @PostMapping(value = "/api/hello", consumes = MediaType.APPLICATION_JSON_VALUE)
    public Hello helloPost(@RequestBody Hello hello) {
        return helloRepository.saveAndFlush(hello);
    }

}
