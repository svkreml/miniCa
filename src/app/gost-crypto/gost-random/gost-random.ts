export class GostRandom {


  constructor() {
  }

  public getRandomValues(array: Uint8Array) {
    return window.crypto.getRandomValues(array);
  }
}
