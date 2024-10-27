# Xenon2


This module provides [Argon2](https://en.wikipedia.org/wiki/Argon2) hashing
support for deno and the web by providing [simple bindings](src/lib.rs) using
[argon2](https://github.com/RustCrypto/password-hashes/tree/master/argon2)
compiled to webassembly.

## Usage

```ts
import { hash } from "jsr:@blckbrry/xenon2@0.2.1";

const encoder = new TextEncoder();

const password = encoder.encode("here's a very cool password");
const salt = encoder.encode("xenon2's so cool");

console.log(hash(password, salt));

// Should log:
// $argon2id$v=19$m=65535,t=2,p=1$QUFBQUFBQUE$giezLHyUS1hf0bymGewGrdThGi+OurBH25GK58fU9n0
```

## Maintainers

- Skyler Calaman ([@skylercalaman](https://github.com/Blckbrry-Pi))

### Original package layout by:

- Elias Sjögreen ([@eliassjogreen](https://github.com/eliassjogreen))
## Other

### Contribution

Pull request, issues and feedback are very welcome. Code style is formatted with
`deno fmt` and commit messages are done following
[Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) spec.

### Licence

Copyright 2021, the denosaurs team. All rights reserved. MIT license.
Copyright 2024, Skyler Calaman. All rights reserved. MIT license.
