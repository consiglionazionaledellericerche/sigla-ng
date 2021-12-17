package it.cnr.rsi.web;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/sso")
public class SSOResource {

    private static final Logger LOGGER  = LoggerFactory.getLogger(SSOResource.class);

    @GetMapping("/login")
    public ResponseEntity<UserDetails> account() {
        LOGGER.info("get account");
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        LOGGER.info("get account with authentication {}", authentication);
        return ResponseEntity.ok().body(null);
    }
}
