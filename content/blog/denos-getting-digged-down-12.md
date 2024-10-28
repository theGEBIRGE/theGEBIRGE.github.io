+++
title = "Denos Getting Digged Down 12"
author = ["Frederic Linn"]
date = 2024-10-28T14:12:00+01:00
draft = false
+++

My first couple of articles all deal with low-level binary shenanigans. To this day, I think the allure of binary exploitation is [very strong](https://github.blog/security/vulnerability-research/from-object-transition-to-rce-in-the-chrome-renderer/). Still, I've shifted more towards application and web security in the following years.

In this article, both things come together. Sort of.
We're looking at the JavaScript runtime `Deno`, specifically at its ability to produce stand-alone binaries.

The article acts as a companion piece to [Deno Dig](https://github.com/theGEBIRGE/DenoDig), a tool I've recently wrote which is able to extract application code and npm packages from said binaries.
It does so on every platform (including a web version) and for every version of `Deno`.

But before we get ahead of ourselves...


### What is Deno? {#what-is-deno}

> Deno is the open-source JavaScript runtime for the modern web.

Ryan Dahl, the creator of `Node.js`, announced `Deno` in 2018 after [talking](https://www.youtube.com/watch?v=M3BM9TB-8yA) of 10 things he regrets about the former.

`Deno` strives to be secure by default, which is why sensible APIs like file access and networking are all opt-in.
The dangers of running untrusted code should be as minimal as possible.

Other differentiators are built-in features like a code linter, a code formatter, a language server and an extensive standard library.

In essence, `Deno` provides a more curated, more secure and generally more cohesive package than `Node's` wild west ecosystem.

Oh, it also just released version 2.0.


### Deno Compile {#deno-compile}

`Deno` applications can be [compiled](https://docs.deno.com/runtime/reference/cli/compiler/) into stand-alone executables. This is useful for environments where the runtime is not available.

Up until recently, it worked by appending the application code to a binary and extracting it at runtime. Akin to what we did with our `Linux.Doomsday` [virus](/blog/modifying-binaries-part-3/).

A special executable called `denort` ("Deno runtime") is used as the host for the application code. It is a stripped-down version of the normal `Deno` executable (no linter etc). Versions for a number of operating systems/architectures exist and are part of every new release (see [assets](https://github.com/denoland/deno/releases/tag/v2.0.2)).

Those different versions allow for [cross compilation](https://docs.deno.com/runtime/reference/cli/compiler/#supported-targets): Executables for foreign targets are simply [fetched](https://github.com/denoland/deno/pull/9141) and the application code is added. No _actual_ compilation step needed.

The feature was [introduced](https://deno.com/blog/v1.6#deno-compile-self-contained-standalone-binaries) in version `1.6.0` and has gone through a few iterations since then:

-   `>=1.6.0 <1.7.0`: Bundle appended to the Deno binary
-   `>=1.7.0 <1.33.3`: Metadata + bundle appended to the Deno binary
-   `>=1.33.3 <1.46`: eszip appended to the Deno binary (introduction of npm package support)
-   `>` 1.46=: eszip included in an object file section of the Deno binary (needed for code signing)

`Node.js` has a similar feature, but it's experimental and you need a [PhD](https://nodejs.org/api/single-executable-applications.html) in order to use it.


### Handling Appended Data (&lt; Deno 1.46) {#handling-appended-data--deno-1-dot-46}

Extracting an appended bundle is pretty simple. We're going to look at an example for version `1.6.0`, but the process is mostly the same for the other ones.

The last 16 bytes of a stand-alone binary have the following format:

```text
 | Magic (8) | Bundle Offset  (8) |
```

The first eight _magical_ bytes are always `d3n0l4nd`. The following eight bytes are the starting position of the bundled application data. Those bytes can be taken _as is_, meaning they are `big-endian`.

Let's manually extract a bundle for clarification:

```sh { linenos=true, linenostart=1, hl_lines=["1","4","7","12","28"] }
$ file hello-v1.6.exe
hello-v1.6.exe: PE32+ executable (console) x86-64, for MS Windows

$ tail -c 16 hello-v1.6.exe | xxd
00000000: 6433 6e30 6c34 6e64 0000 0000 01f6 a600  d3n0l4nd........

$ dd if=hello-v1.6.exe of=bundle.js skip=0x1f6a600 bs=1
525+0 records in
525+0 records out
525 bytes transferred in 0.002867 secs (183118 bytes/sec)

$ cat bundle.js
function generateRandomString(length = 10) {
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    const charactersLength = characters.length;
    for(let i = 0; i < length; i++){
        const randomIndex = Math.floor(Math.random() * charactersLength);
        result += characters.charAt(randomIndex);
    }
    return result;
}
function greet(name) {
    return `Hello, ${name}!`;
}
const name = generateRandomString();
console.log(greet(name));
d3n0l4nd��%
```

We extract the magical delimiter and bundle offset pointer (`0x1f6a600`) in line four. Afterwards, we use `dd` to extract the bundle. Because we extract everything to the end of the file, delimiter and offset pointer are also present in line 28.


### Handling Injected Data (&gt;= Deno 1.46) {#handling-injected-data--deno-1-dot-46}

Simply appending the data has a couple of drawbacks, but the main one is missing support for code signing on `Winows` and `macOS`.

Because of this, the implementation nowadays doesn't append the data but injects it into proper sections of the object file. A discussion can be found in the [pull request](https://github.com/denoland/deno/pull/24604/commits/240cb365b730d0c44c115d4f4e045369938a7a80#diff-fc607f903b2dfca3e91ceef543a99b74214ee727e19b472384a2c084d5a9da1b).
Under the hood it uses [sui](https://github.com/denoland/sui), an injection tool now part of `Deno`.

Different object file formats need different handling:

-   `ELF`: Appended to the end of the binary (like before)
-   `Mach-O`: A new section named `d3n0l4nd` is created
-   `PE`: A new `RC DATA` resource is created in the `.pedata` section

Thankfully, the [object](https://github.com/gimli-rs/object) crate provides us with mostly straightforward means of extracting the data.

`PE` files, however, deserve some additional remarks: Resources are usually part of the [.rsrc](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#the-rsrc-section) section. It took me a while to realize that in `Deno's` case, a custom `.pedata` section is used.
Probably because of [this](https://github.com/Systemcluster/editpe/blob/f3b591beae74cadada8ef98ed2d7d937e1c44bd0/src/image.rs#L526) dependency.

Let's have a look at a `Deno` executable with `PE-bear`:

{{< figure src="/denos-getting-digged-down-12_pe-bear.png" >}}

As we can see, `.pedata` contains the `D3N0L4ND` `Resource Directory Entry`. That entry contains a table which points to a `Resource Data Description`.
_It_ contains an offset (calculated from the start of the **section**) and a total size.

With that information, we can finally extract the blob we're interested in.

Well, not quite yet! The offset is actually a [relative virtual address](https://stackoverflow.com/a/2174223) (`RVA`), which means we have to translate it into a _file offset_.

Apart from the `RVA` and size of our blob, we also need two additional pieces of information:

1.  `RVA` of the containing section (`.pedata`)
2.  pointer to the raw section data

Afterwards we're finally able to calculate the start of our blob (pinky swear!) by applying the following formular:

```txt
 (RVA of the resource) - (virtual address of .pedata) + (raw data pointer of .pedata)
```

But what exactly are we extracting anyway?


### ¿Qué es un eszip? {#qué-es-un-eszip}

> A compact file format to losslessly serialize an ECMAScript module graph into a single file

In other words: Eszip is the homebrew format used for storing our loot and a lot of metadata surrounding it.

Here's the file format taken from their [repository](https://github.com/denoland/eszip?tab=readme-ov-file#file-format):

```text
 | Magic (8) | Header size (4) | Header (n) | Header hash (32) | Sources size (4) | Sources (n) | SourceMaps size (4) | SourceMaps (n) |

 Header:
 ( | Specifier size (4) | Specifier (n) | Entry type (1) | Entry (n) | )*

 Entry (redirect):
 | Specifier size (4) | Specifier (n) |

 Entry (module):
 | Source offset (4) | Source size (4) | SourceMap offset (4) | SourceMap size (4) | Module type (1) |

 Sources:
 ( | Source (n) | Hash (32) | )*

 SourceMaps:
 ( | SourceMap (n) | Hash (32) | )*
```

Because the online [eszip-viewer](https://eszip-viewer.deno.dev) doesn't appear to work at the time of writing, we need to use the CLI version.

Let's create an eszip file first:

```sh { linenos=true, linenostart=1, hl_lines=["14"] }
$ cargo run --example eszip_builder https://deno.land/x/cowsay/cowsay.ts cow.eszip2

    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.33s
     Running `target/debug/examples/eszip_builder 'https://deno.land/x/cowsay/cowsay.ts' cow.eszip2`
source: https://deno.land/x/cowsay@1.1/cowsay.ts
source: https://deno.land/x/cowsay@1.1/mod.ts
source: https://deno.land/x/cowsay@1.1/src/balloon.ts
source: https://deno.land/x/cowsay@1.1/src/cows.ts
source: https://deno.land/x/cowsay@1.1/src/replacer.ts
source: https://deno.land/x/cowsay@1.1/src/cows/cows.ts
source: https://deno.land/x/cowsay@1.1/src/faces.ts
source: https://deno.land/std@0.224.0/flags/mod.ts
source: https://deno.land/std@0.224.0/assert/assert_exists.ts
source: https://deno.land/std@0.224.0/assert/assertion_error.ts
source: https://deno.land/x/cowsay@1.1/src/models/IOptions.ts
source: https://deno.land/std/flags/mod.ts
source: https://deno.land/x/cowsay/cowsay.ts

$ du -sh cow.eszip2
 88K    cow.eszip2
```

Now we can look at the contents in a human friendly way:

```sh
 $ cargo run --example eszip_viewer cow.eszip2 > cow.txt
```

The output is quite long, so I'll only show the section for the `assertion_error.ts` module (line 14 above).

```txt { linenos=true, linenostart=1077 }
// cow.txt
============
Specifier: https://deno.land/std@0.224.0/assert/assertion_error.ts
Kind: JavaScript
---
// Copyright 2018-2024 the Deno authors. All rights reserved. MIT license.
// This module is browser compatible.
/**
 * Error thrown when an assertion fails.
 *
 * @example
 * ```ts
 * import { AssertionError } from "https://deno.land/std@$STD_VERSION/assert/assertion_error.ts";
 *
 * throw new AssertionError("Assertion failed");
 * ```
 */ export class AssertionError extends Error {
  /** Constructs a new instance. */ constructor(message){
    super(message);
    this.name = "AssertionError";
  }
}

---
{"version":3,"sources":["https://deno.land/std@0.224.0/assert/assertion_error.ts"],"sourcesContent":["// Copyright 2018-2024 the Deno authors. All rights reserved. MIT license.\n// This module is browser compatible.\n\n/**\n * Error thrown when an assertion fails.\n *\n * @example\n * ```ts\n * import { AssertionError } from \"https://deno.land/std@$STD_VERSION/assert/assertion_error.ts\";\n *\n * throw new AssertionError(\"Assertion failed\");\n * ```\n */\nexport class AssertionError extends Error {\n  /** Constructs a new instance. */\n  constructor(message: string) {\n    super(message);\n    this.name = \"AssertionError\";\n  }\n}\n"],"names":[],"mappings":"AAAA,0EAA0E;AAC1E,qCAAqC;AAErC;;;;;;;;;CASC,GACD,OAAO,MAAM,uBAAuB;EAClC,+BAA+B,GAC/B,YAAY,OAAe,CAAE;IAC3B,KAAK,CAAC;IACN,IAAI,CAAC,IAAI,GAAG;EACd;AACF"}
============
```

Cool.


### ¿Qué son los metadatos? {#qué-son-los-metadatos}

Apart from the ezip, there's also some structured metadata contained in the binary. It holds information about permissions, arguments and general configuration:

```js { linenos=true, linenostart=1 }
{
  "argv": [],
  "seed": null,
  "permissions": {
    "allow_all": true,
    "allow_env": [],
    "deny_env": null,
    "allow_hrtime": true,
    "deny_hrtime": false,
    "allow_ffi": [],
    "deny_ffi": null,
    "allow_net": [],
    "deny_net": null,
    "allow_read": [],
    "deny_read": null,
    "allow_run": [],
    "deny_run": null,
    "allow_sys": [],
    "deny_sys": null,
    "allow_write": [],
    "deny_write": null,
    "no_prompt": false
  },
  "location": null,
  "v8_flags": [],
  "log_level": null,
  "ca_stores": null,
  "ca_data": null,
  "unsafely_ignore_certificate_errors": null,
  "maybe_import_map": null,
  "entrypoint": "file:///home/runner/work/telecraft/telecraft/packages/cli/index.ts",
  "node_modules": {
    "Managed": {
      "node_modules_dir": false,
      "package_json_deps": null
    }
  },
  "disable_deprecated_api_warning": false,
  "unstable_config": {
    "legacy_flag_enabled": false,
    "bare_node_builtins": false,
    "byonm": false,
    "sloppy_imports": false,
    "features": [
      "kv"
    ]
  }
}
```

In this case, there's not much to see. But we can spot the `unstable kv` feature from my guinea pig project's [README](https://github.com/MadrasMC/telecraft?tab=readme-ov-file#building-from-source-optional).


### ¿Qué es un sistema de archivos virtual? {#qué-es-un-sistema-de-archivos-virtual}

Lastly, let's have a quick look at how `npm` packages are serialized. A virtual file system (vfs) is used to represent the `node_modules` folder.

That vfs uses `JSON` and looks like this:

```js { linenos=true, linenostart=1, hl_lines=["22-24"] }
{
"name": "node_modules",
"entries": [{
    "Dir": {
        "name": "registry.npmjs.org",
        "entries": [{
            "Dir": {
            "name": "@discordjs",
            "entries": [{
                "Dir": {
                    "name": "builders",
                    "entries": [{
                        "Dir": {
                        "name": "1.8.2",
                        "entries": [{
                            "File": {
                                "name": "LICENSE",
                                "offset": 14050230,
                                "len": 10788}},
                            {
                            "File": {
                                "name": "README.md",
                                "offset": 14061018,
                                "len": 3529}},
                            {
                            "File": {
                                "name": "package.json",
                                "offset": 14064547,
                                "len": 2809
                            }}]}}]}}]}}]}}]}
```

The original file has 28690 lines after prettyfication!

As you'd expect, the vfs supports three different types of nodes, `Directories`, `Files` and `Symlinks`. Files have a name, a length and an offset.


### ¿Qué? {#qué}

Enough theory! What problem does the `Deno Dig` tool solve? What's the elevator pitch?

-   **LEVEL THE PLAYING FIELD IN TODAY'S WORLD OF CYBER-KINETIC CAPABILITIES**
-   **ZERO TRUST EXTRACTION OF APPLICATION CODE AND NPM PACKAGES**
-   **HANDLES EVERY PERMUTATION IN THE IMPLEMENTATION SPACE OF `deno compile`**
-   **RUNNABLE ON THE EDGE THANKS TO WASM VERSION**
-   **TRUE CROSS-PLATFORM (WANT TO USE THE MACH-O BUILD TO HANDLE PE FILES? YOU CAN!)**

Here's a demo video showing the command line version in action:

<video controls preload="metadata" muted><source src="/denos-getting-digged-down-12_demo.mp4" type="video/mp4">
Your browser does not support the video tag.</video>

Pretty fast, right? That's because it's written in Rus... HOLD ON! There's a reason.

Besides borrowing some structs from `Deno` itself, we can also make use of the `eszip` crate. This way, we don't have to re-invent parsing and are future-proof should changes in their format arise.

If we already use `eszip`, why don't we also use the `sui` crate? Great question!

Like always, `PE` files are to blame. `Sui` is designed to extract sections from the binary _it's part of_. In case of `PE` files, it's assumed that those run under Windows.

Fair enough.

But based on that assumption, they make use of platform specific [APIs](https://github.com/denoland/sui/blob/b827f5e639bf51bc26855512a8b4399076521aec/lib.rs#L271).
That's why we use the `object` crate instead: It allows for extraction on all platforms.

`Deno Dig` versions for many platforms exist, but why not simply check out the [web version](/deno-dig)?

I hope people find a use for the tool. If something's missing or not working, please let me know directly or via `GitHub` issues.


### Resources and Acknowledgments {#resources-and-acknowledgments}

-   `Deno Land` for creating an awesome project and letting me borrow some structs
-   A [talk](https://www.youtube.com/watch?v=RKjVcl62J9w) about `deno compile` by the author of the `sui` crate
-   [@h0ng10](https://infosec.exchange/@h0ng10) for the initial idea and proofreading this article
