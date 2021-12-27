import { Injectable } from '@angular/core';
import { Http, Response } from '@angular/http';
import { Observable } from 'rxjs/Rx';
import { SERVER_API_URL } from '../../app.constants';
import { Headers } from '@angular/http';

@Injectable()
export class AccountService  {
    constructor(private http: Http) { }
    headers: Headers = new Headers ({
        'Access-Control-Allow-Origin': '*'
    });

    get(user?: string): Observable<any> {
        let url = 'api/account';
        if (user) {
            url += '/' + user;
        }
        return this.http.get(url, { headers: this.headers}).map((res: Response) => res.json());
    }

    save(account: any): Observable<Response> {
        return this.http.post(SERVER_API_URL + 'api/account', account);
    }
}
