import {Component, OnInit} from '@angular/core';
import {CertReqDto} from '../dto/cert-req-dto';
import {Alg} from '../dto/algs.enum';


import {CertDto} from '../dto/cert-dto';
import {GostRandom} from '../gost-crypto/gost-random';

@Component({
  selector: 'app-generate-certificate',
  templateUrl: './generate-certificate.component.html',
  styleUrls: ['./generate-certificate.component.css']
})
export class GenerateCertificateComponent implements OnInit {


  constructor() {
  }

  algs: Alg[] = Alg.getAlgs();

  model = new CertReqDto();

  output: CertDto;

  onSubmit() {
    const a = new Uint8Array(10);

    GostRandom.getRandomValues(a);

    console.log(a);
  }

  ngOnInit(): void {
  }
}
