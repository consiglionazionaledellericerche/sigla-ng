import { Component, OnInit } from '@angular/core';

@Component({
    selector: 'jhi-page-ribbon',
    template: `<div class="ribbon" *ngIf="ribbonEnv"><a href="" jhiTranslate="global.ribbon.{{ribbonEnv}}">{{ribbonEnv}}</a></div>`
})
export class PageRibbonComponent implements OnInit {

    ribbonEnv: string;

    constructor() {}

    ngOnInit() {
    }
}
