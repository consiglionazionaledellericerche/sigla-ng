import { Injectable } from '@angular/core';
import { Principal } from './principal.service';
import { HttpClient } from '@angular/common/http';

@Injectable()
export class AuthService {

    constructor(
        private principal: Principal,
        private http: HttpClient,
    ) {}

    authorize(force) {
        const authReturn = this.principal.identity(force).then(authThen.bind(this));

        return authReturn;

        function authThen() {
            const isAuthenticated = this.principal.isAuthenticated();
            const toStateInfo = this.stateStorageService.getDestinationState().destination;

            // an authenticated user can't access to login and register pages
            if (isAuthenticated && (toStateInfo.name === 'register')) {
                this.router.navigate(['']);
                return false;
            }

            // recover and clear previousState after external login redirect (e.g. oauth2)
            const fromStateInfo = this.stateStorageService.getDestinationState().from;
            const previousState = this.stateStorageService.getPreviousState();
            if (isAuthenticated && !fromStateInfo.name && previousState) {
                this.stateStorageService.resetPreviousState();
                this.router.navigate([previousState.name], { queryParams:  previousState.params  });
                return false;
            }

            if (toStateInfo.data.authorities && toStateInfo.data.authorities.length > 0) {
                return this.principal.hasAnyAuthority(toStateInfo.data.authorities).then((hasAnyAuthority) => {
                    if (!hasAnyAuthority) {
                        if (isAuthenticated) {
                            // user is signed in but not authorized for desired state
                            this.router.navigate(['accessdenied']);
                        } else {
                            // user is not authenticated. Show the state they wanted before you
                            // send them to the login service, so you can return them when you're done
                            const toStateParamsInfo = this.stateStorageService.getDestinationState().params;
                            this.stateStorageService.storePreviousState(toStateInfo.name, toStateParamsInfo);
                            // now, send them to the signin state so they can log in
                            this.router.navigate(['']);
                        }
                    }
                    return hasAnyAuthority;
                });
            }
            return true;
        }
    }
}
