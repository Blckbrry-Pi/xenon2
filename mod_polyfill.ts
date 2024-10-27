import buildWithRuntime, { type Argon2Runtime } from "./mod_runtime_agnostic.ts";
export type * from "./mod_runtime_agnostic.ts";
import { WebAssembly } from "@blckbrry/polywasm";

const polyfillRuntime: Argon2Runtime = await buildWithRuntime(WebAssembly as unknown as typeof globalThis.WebAssembly);
const hash = polyfillRuntime.hash;
const verify = polyfillRuntime.verify;

export { hash, verify };
