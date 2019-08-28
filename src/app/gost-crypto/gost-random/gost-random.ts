export class GostRandom {


  constructor() {
  }

  public static getRandomValues(array: Uint8Array) {
    return window.crypto.getRandomValues(array);
  }

  public static getSeed(length: number): ArrayBuffer|Uint8Array|Uint32Array {
        const seed = new Uint8Array(length);
        GostRandom.getRandomValues(seed);
        return seed.buffer;
    }
}
