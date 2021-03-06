import { BrowserModule } from '@angular/platform-browser';
import { NgModule } from '@angular/core';

import { AppComponent } from './app.component';
import { GenerateCertificateComponent } from './generate-certificate/generate-certificate.component';
import {RouterModule, Routes} from '@angular/router';
import { AboutComponent } from './about/about.component';
import { PageNotFoundComponent } from './page-not-found/page-not-found.component';
import {FormsModule} from '@angular/forms';
import { GostCryptoComponent } from './gost-crypto/gost-crypto.component';

const appRoutes: Routes = [
  { path: 'about', component: AboutComponent },
  { path: 'generate-certificate',      component: GenerateCertificateComponent },
  { path: '',
    redirectTo: '/about',
    pathMatch: 'full'
  },
  { path: '**', component: PageNotFoundComponent }
];


@NgModule({
  declarations: [
    AppComponent,
    GenerateCertificateComponent,
    AboutComponent,
    PageNotFoundComponent,
    GostCryptoComponent
  ],
  imports: [
    BrowserModule,
    RouterModule.forRoot(
      appRoutes,
    ),
    FormsModule,
  ],
  providers: [],
  bootstrap: [AppComponent]
})
export class AppModule { }



