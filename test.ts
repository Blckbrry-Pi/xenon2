import { assert, assertEquals } from "jsr:@std/assert@0.221";

import { Argon2Params, hash, verify } from "./mod.ts";

const encoder = new TextEncoder();
const encode = (str: string) => encoder.encode(str);

const password = encode("here's a very cool password");
const password2 = encode("here's a different, less-cool password");
const salt = encode("xenon2's so cool");

const TESTS: [Argon2Params, string][] = [
  [
    { algorithm: "Argon2id", version: 0x13, mCost: 65536 },
    "$argon2id$v=19$m=65536,t=2,p=1$eGVub24yJ3Mgc28gY29vbA$l2g9IkHxa2w5HAL0YuofExQCjELI/9wyYkmrNHhoa28",
  ],
];

for (const [params, digest] of TESTS) {
  const m = params.mCost ? ` m=${params.mCost}` : "";
  const t = params.tCost ? ` t=${params.tCost}` : "";
  const p = params.pCost ? ` p=${params.pCost}` : "";

  const spec = `${params.algorithm} 0x${params.version.toString(16)}${m}${t}${p}`;

  Deno.test({
    name: `Hash   ${spec}`,
    fn: () => {
      assertEquals(
        hash(password, salt, params),
        digest,
      );
    },
  });

  Deno.test({
    name: `Verify ${spec}`,
    fn: () => {
      assert(verify(digest, password));
      assert(!verify(digest, password2));  
    },
  });
}
