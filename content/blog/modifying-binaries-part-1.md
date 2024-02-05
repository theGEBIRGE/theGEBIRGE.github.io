+++
title = "Baby's First Binary Modifications"
author = ["Frederic Linn"]
date = 2021-10-17T22:22:00+02:00
draft = false
+++

<div class="verse">

"There, that hole. Take a closer look."<br />
--- Patches, 'Dark Souls'<br />

</div>

Working with a raw binary has something magical. It's this little black box, created through an arcane process, where all high-level concepts collapse into a single block of bytes.
The thought of poking around in binaries seemed intimidating to me at first, but many great tools and resources exist to aid the learning process. First and foremost I want to mention [Practical Binary Analysis](https://practicalbinaryanalysis.com/) by Dennis Andriesse, which acted as a catalyst for my already prevalent interest in these topics.

Hopefully this post marks the beginning of a series of articles that illustrate my journey into the deep hole that is binary analysis. I'll move slowly and retread old ground, but I want this to be a proper reflection of my learning process. For now we're only working with [ELF](https://en.wikipedia.org/wiki/Executable_and_Linkable_Format) files for x86-64.

This time we're going to look at an example of a misbehaving binary. We're going to learn about two different methods of modifying the binary's behavior. While contrived, it should still highlight the important aspects of analysis and modification.


### The Premise {#the-premise}

I created a simple program that compares two strings:

```C { linenos=true, linenostart=1, hl_lines=["18"] }
// compare.c
#include <stdio.h>
#include <string.h>

int main(int argc, char* argv[])
{
    int res;

    if (argc < 3) {
        printf("usage: %s <str1> <str2>", argv[0]);
        return -1;
    }

    res = strcmp(argv[1], argv[2]);

    if (res == 0) {
        printf("<str1> and <str2> are equal\n");
    } else if (res > 0) {
        printf("<str1> is less than <str2> (%d)\n", res);
    } else {
        printf("<str1> is greater than <str2> (%d)\n", res);
    }

    return 0;
}
```

Unfortunately I always mix up the return value of `strcmp()`. Those man pages[^fn:1], however, are pretty verbose, so I could _not_ be bothered to read up
on it. If the strings don't match, it's either a positive or a negative integer, that much I know. Let's just hope for the best.

```txt { linenos=true, linenostart=1, hl_lines=["3"] }
$ gcc -Wall -Wextra -Werror -O0 -std=c99 -pedantic compare.c -o compare
$ ./compare long longer
<str1> is greater than <str2> (-101)
```

**Damn it!** The first string is certainly not greater. But what's the funny looking number? Okay, okay, it's time to finally read the man page:

```txt { linenos=true, linenostart=1 }
----snip----
strcmp() returns an integer indicating the result of the comparison, as follows:

• 0, if the s1 and s2 are equal;
• a negative value if s1 is less than s2;
• a positive value if s1 is greater than s2.
----snip----
```

Our return value is negative, so `str1` should be _less_ than `str2`[^fn:2]. I knew I'd mess those branches up! There's no way I'm gonna compile the program _again_. So what else can we do about it?


### Method 1: Patching {#method-1-patching}

The first thing we can do is to manually patch the instruction that is responsible for taking the branch. Let's disassemble `main` and have a look at it:

```txt { linenos=true, linenostart=1, hl_lines=["37"] }
$ objdump -M intel --disassemble=main compare
----snip----
0000000000001159 <main>:
    1159:       55                      push   rbp
    115a:       48 89 e5                mov    rbp,rsp
    115d:       48 83 ec 20             sub    rsp,0x20
    1161:       89 7d ec                mov    DWORD PTR [rbp-0x14],edi
    1164:       48 89 75 e0             mov    QWORD PTR [rbp-0x20],rsi
    1168:       83 7d ec 02             cmp    DWORD PTR [rbp-0x14],0x2
    116c:       7f 25                   jg     1193 <main+0x3a>
    116e:       48 8b 45 e0             mov    rax,QWORD PTR [rbp-0x20]
    1172:       48 8b 00                mov    rax,QWORD PTR [rax]
    1175:       48 89 c6                mov    rsi,rax
    1178:       48 8d 05 89 0e 00 00    lea    rax,[rip+0xe89]
    117f:       48 89 c7                mov    rdi,rax
    1182:       b8 00 00 00 00          mov    eax,0x0
    1187:       e8 b4 fe ff ff          call   1040 <printf@plt>
    118c:       b8 ff ff ff ff          mov    eax,0xffffffff
    1191:       eb 7a                   jmp    120d <main+0xb4>
    1193:       48 8b 45 e0             mov    rax,QWORD PTR [rbp-0x20]
    1197:       48 83 c0 10             add    rax,0x10
    119b:       48 8b 10                mov    rdx,QWORD PTR [rax]
    119e:       48 8b 45 e0             mov    rax,QWORD PTR [rbp-0x20]
    11a2:       48 83 c0 08             add    rax,0x8
    11a6:       48 8b 00                mov    rax,QWORD PTR [rax]
    11a9:       48 89 d6                mov    rsi,rdx
    11ac:       48 89 c7                mov    rdi,rax
    11af:       e8 9c fe ff ff          call   1050 <strcmp@plt>
    11b4:       89 45 fc                mov    DWORD PTR [rbp-0x4],eax
    11b7:       83 7d fc 00             cmp    DWORD PTR [rbp-0x4],0x0
    11bb:       75 11                   jne    11ce <main+0x75>
    11bd:       48 8d 05 5c 0e 00 00    lea    rax,[rip+0xe5c]
    11c4:       48 89 c7                mov    rdi,rax
    11c7:       e8 64 fe ff ff          call   1030 <puts@plt>
    11cc:       eb 3a                   jmp    1208 <main+0xaf>
    11ce:       83 7d fc 00             cmp    DWORD PTR [rbp-0x4],0x0
    11d2:       7e 1b                   jle    11ef <main+0x96>
    11d4:       8b 45 fc                mov    eax,DWORD PTR [rbp-0x4]
    11d7:       89 c6                   mov    esi,eax
    11d9:       48 8d 05 60 0e 00 00    lea    rax,[rip+0xe60]
    11e0:       48 89 c7                mov    rdi,rax
    11e3:       b8 00 00 00 00          mov    eax,0x0
    11e8:       e8 53 fe ff ff          call   1040 <printf@plt>
    11ed:       eb 19                   jmp    1208 <main+0xaf>
    11ef:       8b 45 fc                mov    eax,DWORD PTR [rbp-0x4]
    11f2:       89 c6                   mov    esi,eax
    11f4:       48 8d 05 6d 0e 00 00    lea    rax,[rip+0xe6d]
    11fb:       48 89 c7                mov    rdi,rax
    11fe:       b8 00 00 00 00          mov    eax,0x0
    1203:       e8 38 fe ff ff          call   1040 <printf@plt>
    1208:       b8 00 00 00 00          mov    eax,0x0
    120d:       c9                      leave
    120e:       c3                      ret
----snip----
```

Because we disabled optimizations, we pretty much get a one-to-one mapping from our C code to assembly. Our conditions still got re-arranged, resulting in the highlighted **`jle`** instruction instead of our _greater than_ condition.
The instruction is encoded as **`7e 1b`**. The first byte is the instruction itself, the second one the target of the jump. It's a relative offset, meaning the target gets computed like this:

```python { linenos=true, linenostart=1 }
# jump_target.py

next_addr = 0x11d4
offset = 0x1b
target = next_addr + offset
print("jump target: ", hex(target))
```

```text
jump target:  0x11ef
```

Now we know what instruction to patch. But what does the patch look like? Simply inverting the logic should do the trick. Is there a "Jump Greater Than" instruction? Well, of _course_ there is\![^fn:3] Luckily we only have to change a single [nibble](https://en.wikipedia.org/wiki/Nibble). _Actually_ we only have to change a single bit!

```python { linenos=true, linenostart=1 }
# bitflip.py
print(bin(0x7f))
print(bin(0x7e))
```

```text
0b1111111
0b1111110
```

But because we're not [rowhammering](https://en.wikipedia.org/wiki/Row_hammer) or something, our goal stays the same: Turn **`7e`** into **`7f`**.

There are many ways to patch a binary, including convenient ones like using [Ghidra](https://ghidra-sre.org/). But we're all about minimalism here, so let's just use _any_ hex editor.
I'm going with Emacs' hexl-mode. The process stays the same: Find the instruction at offset `0x11d2` and patch it.

Are you finished? Great, me too. Let's see if it worked:

```txt { linenos=true, linenostart=1, hl_lines=["5"] }
$ objdump -M intel --disassemble=main compare_patched
----snip----
    11cc:       eb 3a                   jmp    1208 <main+0xaf>
    11ce:       83 7d fc 00             cmp    DWORD PTR [rbp-0x4],0x0
    11d2:       7f 1b                   jg     11ef <main+0x96>
    11d4:       8b 45 fc                mov    eax,DWORD PTR [rbp-0x4]
    11d7:       89 c6                   mov    esi,eax
----snip----
```

Looks promising, but let's actually run both versions:

```txt { linenos=true, linenostart=1, hl_lines=["5"] }
$ ./compare long longer
<str1> is greater than <str2> (-101)
$ ./compare_patched long longer
<str1> is less than <str2> (-101)
```

We did it!

While certainly a fun exercise, this method of patching the binary directly has many disadvantages.
In our case the process was simple, but what if the new instruction doesn't fit into the space we are given? That's a bad thing, because many instructions rely on offsets that we would break.
It's also a very laborious and error-prone process. We have _one_ call to `strcmp()` in our program, but what if we would have _one million_ calls? Or, well, thirty. Manually patching doesn't scale in those cases.

We need a different, more dynamic approach.


### Method 2: Shared Library Hooking {#method-2-shared-library-hooking}

There are two ways to handle calls to external libraries: The linker either adds those functions to the binary itself (_statically linked_), or the calls get resolved by a dynamic linker at runtime (_dynamically linked_). Without additional flags, `gcc` will choose dynamic linking by default.

We can find out how a program is linked by running _file_ on it:

```txt { linenos=true, linenostart=1, hl_lines=["3"] }
$ file /bin/ls
/bin/ls: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV),
dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2,
BuildID[sha1]=c50003031a2ce019c50810f8abdaefc4d44f9e52,
for GNU/Linux 4.4.0, stripped
```

So `ls` is dynamically linked, but what libraries does it need?

```txt { linenos=true, linenostart=1, hl_lines=["4","5"] }
$ ldd /bin/ls
        linux-vdso.so.1 (0x00007ffdb7ffc000)
        libcap.so.2 => /usr/lib/libcap.so.2 (0x00007fac3a91b000)
        libc.so.6 => /usr/lib/libc.so.6 (0x00007fac3a74f000)
        /lib64/ld-linux-x86-64.so.2 => /usr/lib64/ld-linux-x86-64.so.2 (0x00007fac3a978000)
```

`ldd` tells us that `ls` has four runtime dependencies. In line 4 we can see `libc` and in line 5 `ld-linux`, the dynamic linker/loader itself.
The `.so` extension stands for "shared object". As far as I know, the term is interchangeable with "shared library".

So far, so good. The heading implies that there's a way of hooking into these dynamic calls, so let's start exploring.
The dynamic linker of most Unixes supports the `LD_PRELOAD` environment variable. It will load one or more specified libraries _before_ any others, including `libc` itself. If those preloaded libraries provide a function with the same name as one of the "official" library functions, then this first function will be selected at runtime, allowing us to override _any_ function we want, even things like `printf()` or `sleep()`!

Let's create our own shared object that overrides `strcmp()`.

```C { linenos=true, linenostart=1 }
// fake_strcmp.c
#include <string.h>

// All m... strings are created equal!
int strcmp(const char *s1, const char *s2) {
    return 0;
}
```

Because we're creating a shared object, we have to pass some additional flags to `gcc`:

```txt { linenos=true, linenostart=1, hl_lines=["3"] }
$ gcc -fpic -shared fake_strcmp.c -o fake_strcmp.so
$ file fake_strcmp.so
fake_strcmp.so: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV),
dynamically linked, BuildID[sha1]=e0010127670ed066679df5ef9a3c4821fed642a8, not stripped
```

We compile it with the `-fpic` flag to let `gcc` create [position independent code](https://en.wikipedia.org/wiki/Position-independent_code), which gives the library greater flexibility with regards to where it can be mapped into memory without overlapping (e.g. with another library).

As we can see in line 3, we successfully created a shared object. Let's test it!

```txt { linenos=true, linenostart=1 }
$ LD_PRELOAD=$PWD/fake_strcmp.so ./compare Bulbasaur Charmander
<str1> and <str2> are equal
```

Yeah, _right_... Anyway, it worked! Even though we messed up the greater or lesser than conditions, at least our program handles the "null return" correctly.
As you can see, we specify an _absolute_ path to the library by prepending our current working directory. Because `LD_PRELOAD` is an environment variable, child processes inherit its value, but they may have a different working directory than their parent process.

While this is fun, it's not that useful. We just _completely_ swapped out the original implementation, which may be a valid use case for some. But we actually _need_ the original functionality. Just, you know, _backwards_!

Remember that `LD_PRELOAD` makes it so that the dynamic linker provides our program with our own implementation of `strcmp()`. But the original one is still available in `libc`, which we of course still link against. So how do we obtain its address?

There is a function that does exactly that: `dlsym()`[^fn:4]. Let's see it in action.

```C { linenos=true, linenostart=1, hl_lines=["2","11","13"] }
// fake_strcmp.c v2
#define _GNU_SOURCE
#include <dlfcn.h>
#include <string.h>

int (*orig_strcmp)(const char*, const char*);

int strcmp(const char *s1, const char *s2) {
    // Dynamically resolve the address of the *next*
    // occurence of the symbol "strcmp".
    if (!orig_strcmp) orig_strcmp = dlsym(RTLD_NEXT, "strcmp");
    // Invert the return value.
    return (orig_strcmp(s1, s2) * -1);
}
```

Reading through the man page gives us a hint: We have to include the `#define` in line 2 _before_ including the `dlfcn` header file. We do this so that we can use the `RTLD_NEXT` handle in line 11, which gives us the _next_ occurrence of a `strcmp` symbol in the list of loaded libraries, if it exists. And because `libc` gets loaded _after_ our own library, we're good to go.

There's another important thing we learned from the man page: We need to specify a `gcc` flag, `-ldl`.
Let's compile and see if we were successful:

```txt { linenos=true, linenostart=1, hl_lines=["3"] }
$ gcc -Wall -fpic -shared -ldl fake_strcmp.c -o fake_strcmp.so
$ LD_PRELOAD=$PWD/fake_strcmp.so ./compare Bulbasaur Charmander
<str1> is less than <str2> (1)
```

Now [that's](/sad-bulbasaur.jpg) more like it! Our fake `strcmp()` calls the real one, inverts its return value and returns _it_. This works, because we're **absolutely** sure that we **always** mixed up the return value in the **same** way throughout the **whole** code base! Talking about contrived examples...

The main benefit of the `LD_PRELOAD` approach over manually patching is that there's one central place for the modification. That said, every change requires recompilation of the library. And we're only able to modify library calls.


### Conclusion {#conclusion}

In this first article we had a look at two simple techniques for binary modification. We've gotten to know some basic tools that aided us in analyzing the problem at hand. While the examples were contrived, the same techniques can be used for more elaborate modifications.

The first method directly modified the binary, while the second method hooked into its library calls. There are countless exciting things we could (and maybe will) do with these two techniques alone, but for now I'm content with this overview. Again, this is mostly basic stuff. However, I'm a firm believer in strong fundamentals, which is exactly why we're taking small steps in this series.

[^fn:1]: `man 3 strncmp`
[^fn:2]: The number is the difference between the ASCII representation of the first mismatched characters. Comparing "ABC" with "BBC" would yield a return value of -1.
[^fn:3]: You can find it [here](http://ref.x86asm.net/coder64.html). And a couple more, too :).
[^fn:4]: `man 3 dlsym`
