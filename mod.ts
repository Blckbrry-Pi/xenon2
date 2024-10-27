import buildWithRuntime, { type Argon2Runtime } from "./mod_runtime_agnostic.ts";
export type * from "./mod_runtime_agnostic.ts";

const nativeRuntime: Argon2Runtime = await buildWithRuntime(WebAssembly);
const hash = nativeRuntime.hash;
const verify = nativeRuntime.verify;

export { hash, verify };
