/*
 * Copyright (C) 2019  Consiglio Nazionale delle Ricerche
 *
 *     This program is free software: you can redistribute it and/or modify
 *     it under the terms of the GNU Affero General Public License as
 *     published by the Free Software Foundation, either version 3 of the
 *     License, or (at your option) any later version.
 *
 *     This program is distributed in the hope that it will be useful,
 *     but WITHOUT ANY WARRANTY; without even the implied warranty of
 *     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *     GNU Affero General Public License for more details.
 *
 *     You should have received a copy of the GNU Affero General Public License
 *     along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package it.cnr.rsi.web;

import it.cnr.rsi.domain.AlberoMain;
import it.cnr.rsi.domain.TreeNode;
import it.cnr.rsi.repository.AlberoMainRepository;
import it.cnr.rsi.security.UserContext;
import it.cnr.rsi.service.AccessoService;
import it.cnr.rsi.service.AlberoMainService;
import it.cnr.rsi.service.UtenteService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;

import javax.annotation.security.RolesAllowed;
import java.util.List;
import java.util.Map;

/**
 * Created by francesco on 07/03/17.
 */

@RestController
public class AlberoMainResource {

    private static final Logger LOGGER = LoggerFactory.getLogger(AlberoMainResource.class);

    public static final String API_ALBERO_MAIN = "/api/tree";

    private final AlberoMainRepository alberoMainRepository;
    private final AccessoService accessoService;
    private final AlberoMainService alberoMainService;
    private final UtenteService utenteService;

    public AlberoMainResource(AlberoMainRepository alberoMainRepository, AlberoMainService alberoMainService, AccessoService accessoService, UtenteService utenteService) {
        this.alberoMainRepository = alberoMainRepository;
        this.alberoMainService = alberoMainService;
        this.accessoService = accessoService;
        this.utenteService = utenteService;
    }


    @GetMapping(API_ALBERO_MAIN)
    public Map<String, List<TreeNode>> tree(){
    	UserContext userDetails = utenteService.getUserDetails();

        LOGGER.info("GET Tree for User: {} esercizio {} and Unita Organizzativa: {}", userDetails.getUsername(), userDetails.getEsercizio(), userDetails.getUo());
        return alberoMainService.tree(userDetails.getUsername(), userDetails.getEsercizio(), userDetails.getUo());
    }

    @PostMapping(value = API_ALBERO_MAIN, consumes = MediaType.APPLICATION_JSON_VALUE)
    public AlberoMain helloPost(@RequestBody AlberoMain alberoMain) {
        return alberoMainRepository.saveAndFlush(alberoMain);
    }

    @DeleteMapping(value = API_ALBERO_MAIN)
    public boolean evictCacheTree() {
        UserContext userDetails = utenteService.getUserDetails();
        accessoService.evictCacheAccessi(userDetails.getUsername(), userDetails.getEsercizio(), userDetails.getUo());
        return alberoMainService.evictCacheTree(userDetails.getUsername(), userDetails.getEsercizio(), userDetails.getUo());
    }

    @DeleteMapping(value = API_ALBERO_MAIN + "/{username}/{esercizio}/{uo}")
    public boolean evictCacheTree(@PathVariable String username, @PathVariable Integer esercizio, @PathVariable String uo) {
        accessoService.evictCacheAccessi(username, esercizio, uo);
        return alberoMainService.evictCacheTree(username, esercizio, uo);
    }
}
