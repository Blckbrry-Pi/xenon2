import { source } from "./wasm.js";
export default async (_WebAssembly: typeof WebAssembly) => {
  const wasmSource = await source(_WebAssembly);

  const { instance } = await _WebAssembly.instantiate(wasmSource, {
    env: {
      panic: (ptr: number, len: number) => {
        const msg = new TextDecoder().decode(
          new Uint8Array(memory.buffer, ptr, len),
        );
        dealloc(ptr, len);
        throw new Error(msg);
      },
    },
  });

  const memory = instance.exports.memory as typeof _WebAssembly.Memory.prototype;
  const alloc = instance.exports.alloc as (size: number) => number;
  const dealloc = instance.exports.dealloc as (
    ptr: number,
    size: number,
  ) => void;

  const setupParams = instance.exports.setup_params as (
    algorithm: number,
    version: number,
    mCost: number,
    tCost: number,
    pCost: number,
  ) => void;

  const hash = instance.exports.hash as (
    passwordPtr: number,
    passwordLen: number,
    saltPtr: number,
    saltLen: number,
    secretPtr: number,
    secretLen: number,
    outputLocPtr: number,
  ) => void;

  const verify = instance.exports.verify as (
    digestPtr: number,
    digestLen: number,
    passwordPtr: number,
    passwordLen: number,
    secretPtr: number,
    secretLen: number,
    matches: number,
  ) => void;

  return { memory, alloc, dealloc, setupParams, hash, verify };
};
