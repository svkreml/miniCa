export class GostRandom {


  constructor() {
  }

  public static getRandomValues(array: Uint8Array) {
    return window.crypto.getRandomValues(array);
  }
}
