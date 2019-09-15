import { async, ComponentFixture, TestBed } from '@angular/core/testing';

import { GenerateKeyPairComponent } from './generate-key-pair.component';

describe('GenerateKeyPairComponent', () => {
  let component: GenerateKeyPairComponent;
  let fixture: ComponentFixture<GenerateKeyPairComponent>;

  beforeEach(async(() => {
    TestBed.configureTestingModule({
      declarations: [ GenerateKeyPairComponent ]
    })
    .compileComponents();
  }));

  beforeEach(() => {
    fixture = TestBed.createComponent(GenerateKeyPairComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
