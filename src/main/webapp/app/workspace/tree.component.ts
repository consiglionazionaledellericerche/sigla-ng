import { Component, OnInit, Input, ViewChild, ViewChildren, QueryList, enableProdMode } from '@angular/core';
import { JhiLanguageService } from 'ng-jhipster';
import { Principal } from '../shared';
import { Leaf } from './leaf.model';
import { WorkspaceService } from './workspace.service';
import { Observable } from 'rxjs/Observable';
import { TreeComponent, TreeNode } from 'angular-tree-component';
import * as _ from 'lodash';
import { TREE_ACTIONS, KEYS, IActionMapping } from 'angular-tree-component';

enableProdMode();

export class SIGLATreeNode {
    id: String;
    name: String;
    children:  TreeNode[];
}

@Component({
    selector: 'jhi-tree',
    templateUrl: './tree.component.html',
    styles: ['.node-wrapper {color: #0066CC;}']
})
export class SIGLATreeComponent implements OnInit {
    isRequesting: boolean;
    account: Account;
    leafs: Map<String, Leaf[]>;
    leafz: Leaf[] = [];
    nodes = [];
    options = {
        actionMapping: {
            mouse: {
                click: null,
                dblclick: null,
                contextmenu: null
            },
            keys: {
            }
        },
        allowDrop: false,
        getChildren: (node: TreeNode) => this.getChildNodes(node.id)
    };
    icons = {
        '0.SERV' : 'fa-cog',
        '0.CFG' : 'fa-cogs',
        '0.PRV' : 'fa-eur',
        '0.DOC' : 'fa-credit-card-alt',
        '0.AMM' : 'fa-credit-card',
        '0.COANCOEP' : 'fa-money',
        '0.IVA' : 'fa-columns',
        '0.CNS' : 'fa-gg-circle',
        '0.RIP' : 'fa-undo'
    };
    @ViewChild(TreeComponent) tree: TreeComponent;

    constructor(
        private jhiLanguageService: JhiLanguageService,
        private workspaceService: WorkspaceService,
        private principal: Principal
    ) {
        this.jhiLanguageService.setLocations(['workspace']);
    }

    searchtree = (text$: Observable<string>) =>
        text$
        .debounceTime(50)
        .map(term => {
            const limit = 10;
            let i = 0;
            const regex = new RegExp(term.replace(/\s/g, '.*'), 'gi');

            return this.leafz.filter(v => {
                if (i > limit) {
                    return false;
                } else {
                    const match = regex.test(v.breadcrumbS);
                    if (match) {
                        ++i;
                    }
                    return match;
                }
            });
        })

    formatter = (leaf: Leaf) => '';

    onSelectLeaf = (leaf: Leaf) => {
        leaf.breadcrumb.map(segment => {
            let leafId = _.keys(segment)[0];
            let node = this.tree.treeModel.getNodeById(leafId);
            this.tree.treeModel.setFocusedNode(node);
            this.tree.treeModel.focusDrillDown();
        });
    }

    ngOnInit() {

        this.isRequesting = true;
        this.workspaceService.getTree().subscribe(
            leafs => {
                this.leafs = leafs;
                const nodes = _.flatten(_.values<Leaf>(this.leafs));
                this.leafz = nodes
                    .filter(node => node.process)
                    .map(node => {
                        node.breadcrumbS = node.breadcrumb.map(segment => _.values(segment)[0]).join(' > ');
                        return node;
                    });
                this.nodes = this.getChildNodes('0');
                this.stopRefreshing();
            }
        );
        this.principal.identity().then((account) => {
            this.account = account;
        });
    }

    private getChildNodes(id): SIGLATreeNode[] {
        return _.map(this.leafs[id], (node: Leaf) => {
            return {
                id: node.id,
                hasChildren: this.leafs[node.id],
                name: node.description,
                children: null // this.getChildNodes(node.id)
            };
        });
    }

    private stopRefreshing() {
        this.isRequesting = false;
    }

    getIcon = (id: string) => {
        return 'fa ' + (this.icons[id] || '') + ' fa-fw';
    }

    getChildren = (id: string) => {
        return this.leafs[id];
    }

}
