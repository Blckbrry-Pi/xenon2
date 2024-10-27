import { encodeBase64 } from "@std/encoding/base64";
import { compress } from "@blckbrry/lz4";

// Generate wasm
{
  const isTiny = !!Deno.env.get("TINY");
  const name = "xenon2";
  
  await new Deno.Command("cargo", {
    
    // args: ["build", "--target", "wasm32-unknown-unknown"],
    args: !isTiny ? ["build", "--release", "--target", "wasm32-unknown-unknown"] : [
      "+nightly", "build",
      "-Z", "build-std=std,panic_abort",
      "-Z", "build-std-features=panic_immediate_abort",
      "--profile", "tiny",
      "--target", "wasm32-unknown-unknown",
    ],
  }).spawn().status;
  
  const targetFolder = Deno.env.get("CARGO_TARGET_DIR") || "target";
  
  const wasm = await Deno.readFile(
    `./${targetFolder}/wasm32-unknown-unknown/${isTiny ? "tiny" : "release"}/${name}.wasm`,
    // `./${targetFolder}/wasm32-unknown-unknown/debug/${name}.wasm`,
  );
  const encoded = encodeBase64(compress(wasm));
  // const encoded = encodeBase64(wasm);
  const js = `// deno-fmt-ignore-file\n// deno-lint-ignore-file
  import { decodeBase64 } from "jsr:@std/encoding@0.221/base64";
  import buildRuntime from "jsr:@blckbrry/lz4@0.1.6/runtime_agnostic";

  export const source = async (WebAssembly) => (await buildRuntime(WebAssembly)).decompress(decodeBase64("${encoded}"));`;
  await Deno.writeTextFile("wasm/wasm.js", js);
}
