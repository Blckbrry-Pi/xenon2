import wasmBuilder from "./wasm/mod.ts";
// import * as wasm from "./wasm/mod.ts";

/**
 * The three different Argon2 algorithm variants as described by [wikipedia](https://en.wikipedia.org/wiki/Argon2):
 *
 * - **Argon2d**: Argon2d maximizes resistance to GPU cracking attacks. It accesses the memory array in a password dependent order, which reduces the possibility of time–memory trade-off (TMTO) attacks, but introduces possible side-channel attacks.
 * - **Argon2i**: Argon2i is optimized to resist side-channel attacks. It accesses the memory array in a password independent order.
 * - **Argon2id**: (default) Argon2id is a hybrid version. It follows the Argon2i approach for the first half pass over memory and the Argon2d approach for subsequent passes. RFC 9106 recommends using Argon2id if you do not know the difference between the types or you consider side-channel attacks to be a viable threat.
 */
export type Argon2Algorithm = "Argon2d" | "Argon2i" | "Argon2id";

/**
 * The two different versions of the Argon2 algorithm:
 *
 * - **0x10**: Version 16, performs overwrites internally.
 * - **0x13** (default): Version 19, performs XOR internally.
 */
export type Argon2Version = 0x10 | 0x13;

export type Argon2Params = {
  algorithm: Argon2Algorithm;
  version: Argon2Version;
  secret?: ArrayBufferLike;
  /**
   * Memory size in 1 KiB blocks. Between 1 and (2^32)-1.
   *
   * When {@link Argon2Params.algorithm} is Argon2i the default is changed to 12288 as per OWASP recommendations.
   *
   * @default 19456
   */
  mCost?: number;
  /**
   * Number of iterations. Between 1 and (2^32)-1.
   *
   * When {@link Argon2Params.algorithm} is Argon2i the default is changed to 3 as per OWASP recommendations.
   *
   * @default 2
   */
  tCost?: number;
  /**
   * Degree of parallelism. Between 1 and 255.
   *
   * @default 1
   */
  pCost?: number;
};

export type HashFunctionType = (password: BufferSource, salt: BufferSource, params?: Argon2Params) => string;
export type VerifyFunctionType = (digest: string, password: BufferSource, secret?: BufferSource) => boolean;

export type Argon2Runtime = { hash: HashFunctionType, verify: VerifyFunctionType };

export default async (_WebAssembly: typeof WebAssembly): Promise<Argon2Runtime> => {
  const wasm = await wasmBuilder(_WebAssembly);

  function bufferSourceArrayBuffer(data: BufferSource) {
    if (ArrayBuffer.isView(data)) {
      return data.buffer;
    } else if (data instanceof ArrayBuffer) {
      return data;
    }

    throw new TypeError(
      `Could extract ArrayBuffer from alleged BufferSource type. Got ${data} instead.`,
    );
  }

  /**
   * Transfers an {@link ArrayBufferLike} to wasm, automatically allocating it in memory.
   *
   * Remember to unallocate the transfered buffer with {@link wasm.dealloc}
   */
  function transfer(buffer: BufferSource): [number, number] {
    const length = buffer.byteLength;
    const pointer = wasm.alloc(length);
    new Uint8Array(wasm.memory.buffer, pointer, length).set(
      new Uint8Array(bufferSourceArrayBuffer(buffer)),
    );
    return [pointer, length];
  }

  function maybeTransfer(buffer?: BufferSource): [number, number] {
    if (buffer != null) {
      return transfer(buffer);
    }
    return [0, 0];
  }


  /**
   * Computes the Argon2 hash digest for the password, salt and parameters.
   */
  function hash(
    password: BufferSource,
    salt: BufferSource,
    params?: Argon2Params,
  ): string {
    params ??= {
      algorithm: "Argon2id",
      version: 0x13,
    };
    // These defaults come from https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#argon2id
    params.mCost ??= params.algorithm === "Argon2i" ? 12288 : 19456;
    params.tCost ??= params.algorithm === "Argon2i" ? 3 : 2;
    params.pCost ??= 1;

    let algorithmBuf: Uint8Array;
    switch (params.algorithm) {
      case "Argon2i":
        algorithmBuf = new TextEncoder().encode("i___");
        break;
      case "Argon2d":
        algorithmBuf = new TextEncoder().encode("d___");
        break;
      case "Argon2id":
        algorithmBuf = new TextEncoder().encode("id__");
        break;
    }
    const algorithm = new DataView(algorithmBuf.buffer).getUint32(0, true); // WASM is little endian
    

    const [passwordPtr, passwordLen] = transfer(password);
    const [saltPtr, saltLen] = transfer(salt);
    const [secretPtr, secretLen] = maybeTransfer(params?.secret);
    const outputLocPtr = wasm.alloc(4); // pointer to output data

    // Load Argon2 params into WASM memory
    wasm.setupParams(
      algorithm,
      params.version,
      params.mCost,
      params.tCost,
      params.pCost,
    );

    wasm.hash(
      passwordPtr,
      passwordLen,
      saltPtr,
      saltLen,
      secretPtr,
      secretLen,
      outputLocPtr,
    );

    wasm.dealloc(passwordPtr, passwordLen);
    wasm.dealloc(saltPtr, saltLen);
    if (secretPtr !== 0) {
      wasm.dealloc(secretPtr, secretLen);
    }

    const outputPtr = new DataView(wasm.memory.buffer, outputLocPtr, 4).getUint32(0, true); // WASM is little endian
    wasm.dealloc(outputLocPtr, 4);
    
    const outputMemory = new DataView(wasm.memory.buffer, outputPtr);
    let outputSize = 0;
    for (outputSize = 0; outputMemory.getUint8(outputSize); outputSize++);

    // Copy output from wasm memory into js
    const outputBuf = new ArrayBuffer(outputSize);
    new Uint8Array(outputBuf).set(
      new Uint8Array(wasm.memory.buffer, outputPtr, outputSize),
    );
    wasm.dealloc(outputPtr, outputSize + 1);

    return new TextDecoder().decode(outputBuf);
  }

  /**
   * Verifies an Argon2 password for a hash digest.
   */
  function verify(
    digest: string,
    password: BufferSource,
    secret?: BufferSource
  ): boolean {
    const [digestPtr, digestLen] = transfer(new TextEncoder().encode(digest));
    const [passwordPtr, passwordLen] = transfer(password);
    const [secretPtr, secretLen] = maybeTransfer(secret);
    const matchesPtr = wasm.alloc(4); // pointer to output data

    wasm.verify(
      digestPtr,
      digestLen,
      passwordPtr,
      passwordLen,
      secretPtr,
      secretLen,
      matchesPtr,
    );

    wasm.dealloc(digestPtr, digestLen);
    wasm.dealloc(passwordPtr, passwordLen);
    if (secretPtr !== 0) {
      wasm.dealloc(secretPtr, secretLen);
    }

    const matches = !!new DataView(wasm.memory.buffer, matchesPtr, 4).getUint32(0, true); // WASM is little endian
    wasm.dealloc(matchesPtr, 4);

    return matches;
  }

  return { hash, verify };
};
