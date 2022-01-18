import { Injectable } from '@angular/core';
import { Http, Response, Headers, URLSearchParams } from '@angular/http';
import { Observable } from 'rxjs/Rx';
import { ProfileService } from '../../layouts/profiles/profile.service';
import { Account, UserContext } from '../../shared';

@Injectable()
export class AuthServerProvider {
    headers = new Headers ({
        'Content-Type': 'application/x-www-form-urlencoded'
    });
    constructor(
        private http: Http,
        private profileService: ProfileService
    ) {
    }

    login(credentials): Observable<any> {
        const data = 'j_username=' + encodeURIComponent(credentials.username) +
            '&j_password=' + encodeURIComponent(credentials.password) +
            '&remember-me=' + credentials.rememberMe + '&submit=Login';
        return this.http.post('api/authentication', data, {
            headers: this.headers
        });
    }

    loginWildfly(credentials, userContext: UserContext): Observable<any> {
        const data = 'j_username=' + encodeURIComponent(credentials.username) +
            '&j_password=' + encodeURIComponent(credentials.password);
        return this.profileService.getProfileInfo().switchMap((profileInfo) => {
            return this.http.post(profileInfo.siglaWildflyURL + '/SIGLA/restapi/login', data, {
                headers: this.headers, withCredentials: true
            });
        });
    }

    initializeWildfly(account: Account): Observable<any> {
        const params: URLSearchParams = new URLSearchParams();
        params.set('comando', 'doDefault');
        params.set('datetime', String(Date.now()));
        if (account && account.access_token) {
            params.set('access_token', account.access_token);
        }
        return this.profileService.getProfileInfo().switchMap((profileInfo) => {
            return this.http.get(profileInfo.siglaWildflyURL + '/SIGLA/Login.do', {
                search: params, headers: this.headers, withCredentials: true
            });
        });
    }

    loginMultiploWildfly(utenteMultiplo: string, userContext: UserContext): Observable<any> {
        const data = 'main.utente_multiplo=' + utenteMultiplo +
            '&context.esercizio=' + userContext.esercizio +
            '&context.cds=' + userContext.cds +
            '&context.uo=' + userContext.uo +
            '&context.cdr=' + userContext.cdr +
            '&comando=doEntraUtenteMultiplo';
        return this.profileService.getProfileInfo().switchMap((profileInfo) => {
            return this.http.post(profileInfo.siglaWildflyURL + '/SIGLA/Login.do', data, {
                headers: this.headers, withCredentials: true
            });
        });
    }

    logoutWildfly(): Observable<any> {
        return this.profileService.getProfileInfo().switchMap((profileInfo) => {
            return this.http.post(profileInfo.siglaWildflyURL + '/SIGLA/GestioneMenu.do', 'comando=doLogout', {
                headers: this.headers, withCredentials: true
            });
        });
    }

    logout(): Observable<any> {
        // logout from the server
        return this.http.post('api/logout', {}).map((response: Response) => {
            // to get a new csrf token call the api
            this.http.get('api/account').subscribe(() => {}, () => {});
            return response;
        });
    }
}
