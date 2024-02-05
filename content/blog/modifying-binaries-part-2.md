+++
title = "Moving Link Through Binary Instrumentation"
author = ["Frederic Linn"]
date = 2021-12-13T11:16:00+01:00
draft = false
+++

<div class="verse">

"I want to be inside your darkest everything."<br />
--- Frida Kahlo, 'The Diary of Frida Kahlo'<br />

</div>

Focusing on a tool sometimes gets a bad rap. There's always this faint aura of [incompetence](https://en.wikipedia.org/wiki/Script_kiddie) present. In the previous article I've already talked about believing in strong fundamentals, which means learning what's _actually going on_ instead of learning how to use a tool someone else has written. In the end, though, it's all about the mindset. If we gain some knowledge and understanding while also learning how to use the new tool, I think it's perfectly fine to spend some quality time with it.

And spending some quality time we will! This is quite the lengthy article that highlights my _journey_ more than anything. I've tried to be as explicit as possible, but there might still be things I simply assume. The truth is, I have no idea who (if anyone) reads this article, so it might not strike the perfect balance. If there are any questions, please [holla at me](/about).

With that out of the way, let's get to know today's star: The _world-class dynamic instrumentation toolkit_ `Frida`.


### Introduction to Frida {#introduction-to-frida}

`Frida` is a "dynamic instrumentation toolkit for developers, reverse-engineers, and security researchers" created by [Ole André V. Ravnås](https://twitter.com/oleavr). What does that mean, though? It means `Frida` lets us inject snippets of `JavaScript` into a running process in order to gather information or change its behavior. Don't worry if that sounds a little abstract, we'll get there over the course of this article.

`Frida` comes with a ton of features and different APIs, which are all neatly documented over at the project's [website](https://frida.re/docs/home/). Let's quickly set the stage for what features we're actually using, in case someone is already familiar with `Frida`:

We're mainly dealing with the `Interceptor` and `NativeFunction` APIs and some other functionality to make those work. With regards to our [mode of operation](https://frida.re/docs/modes/), we're only using _injected_ today.

Now let's begin our journey!


### Mimicking LD_PRELOAD {#mimicking-ld-preload}

[Last time](/blog/modifying-binaries-part-1) we used `LD_PRELOAD` to hook into shared library functions. In order to get to know `Frida`, let's simply try to mimic this behavior.
Why not start with a variation of one of the first [programs](https://inventwithpython.com/invent4thed/chapter3.html) I've ever copied[^fn:1]:

```C { linenos=true, linenostart=1, hl_lines=["10","13"] }
// guess.c
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int main (void) {
    int guess;
    int rnd;

    srand(time(NULL));

    while (1) {
        rnd = (rand() % 10) + 1;

        printf("Enter a number between 1 and 10: ");
        // TODO: Validate input.
        scanf("%d", &guess);

        if (guess < 1 || guess > 10) {
            printf("You heard me!\n");
            continue;
        }
        if (guess == rnd) {
            printf("You guessed right!\n");
            break;
        } else {
            printf("Bad luck, try again!\n");
        }
    }
    return 0;
}
```

A simple _guess the number_ game, that's it. We seed the random number generator with the current time in line 10 and create a new value on every loop iteration in line 13.
Let's compile the program and give it a try.

```txt { linenos=true, linenostart=1 }
$ gcc -Wall -Wextra -Werror -O0 -std=c99 -pedantic guess.c -o guess
$ ./guess
Enter a number between 1 and 10: 0
You heard me!
Enter a number between 1 and 10: 1
Bad luck, try again!
Enter a number between 1 and 10: 2
Bad luck, try again!
Enter a number between 1 and 10: 3
Bad luck, try again!
----snip----
Enter a number between 1 and 10: 3
You guessed right!
```

Finally! That endless loop made me _really_ anxious, though. We could have [interrupted](https://en.wikipedia.org/wiki/Signal_(IPC)#SIGINT) the process by pressing `CTRL + C`, but what about that nagging feeling of utter _defeat_ in the back of our heads? So let's escape the loop by winning **EVERY**. **SINGLE**. **TIME**!

We have a few options. We could overwrite `time()` to always return a predefined value, which makes the random number generation predictable. But that would be a very roundabout way of cheating. Let's just make `rand()` return whatever we please!

It's time to meet the _real_ star of this article: `Frida's` [Interceptor](https://frida.re/docs/javascript-api/#interceptor) API. Reading the documentation, we immediately see two interesting methods: `Interceptor.attach()` and `Interceptor.replace()`. While the latter is more akin to our first experiments with `LD_PRELOAD`, we're still going to start with the former. It's a lot flashier, that's why!

`Interceptor.attach()` enables us to hook into an arbitrary function of the target process, meaning we can read and modify the state in the context of said process. The documentation gives us the function's signature:
`Interceptor.attach(target, callbacks[, data])`

So in order to make this work, we first need to provide the `target`, which is a [NativePointer](https://frida.re/docs/javascript-api/#nativepointer) to the function we want to intercept. There are a couple of different ways to get hold of such a pointer. We want to intercept `rand()`, a standard library function, so we simply get its address from `libc` itself. Because we're injecting into a running process, there's no need to worry about [ASLR](https://en.wikipedia.org/wiki/Address_space_layout_randomization).

The next argument is `callbacks`, an object that can hold two functions, `onEnter` and `onLeave`. The names should be pretty self-explanatory. The former gets executed before the actual function _runs_ (which lets us modify the arguments),  while the latter gets executed before the function _returns_ (which lets us modify the return value). Let's look
at a simple example script:

```js { linenos=true, linenostart=1, hl_lines=["5","12"] }
// rng.js
const randAddr = Module.getExportByName("libc.so.6", "rand");

Interceptor.attach(randAddr, {
    onEnter: function(args) {
        // We can inspect or modify the arguments.
    },
    onLeave: function(returnValue) {
        // We can inspect...
        console.log("Original rand() value: ", returnValue);
        //  ...or modify the return value.
        returnValue.replace(0);
    },
});
```

In line 5 we defined `onEnter()`. Even though its body is empty, we still pay a performance penalty. That's because `Frida` sets up a bunch of things in the background. So in this case, we would be better off to just remove it. What we actually _use_ is `onLeave()`, where we change the return value in line 12.

Using `Interceptor.attach()` this way is kind of redundant, because all we do is returning `0` every time. It's still a lot flashier and we will look at more elaborate examples later on.

So now that we have our script ready, we can politely ask `Frida` to inject it for us. They say a picture is worth a thousand words. So what about a thousand pictures?

<video controls preload="metadata"><source src="/frida-guess.mp4" type="video/mp4">
Your browser does not support the video tag.</video>

We won! Let's quickly recap what happened: On the bottom we start our guessing game and interact with it. Afterwards we start `Frida` on the top by providing the process name and a script to load via the `-l`-flag. This loads the above script into our `guess` process. So now every time our program calls `rand()`, the script's code gets executed. In this case we simply return `0`, which means an input of `1` will let us win[^fn:2] **EVERY**. **SINGLE**. **TIME**!

But let's take a step back. What actually _happened_ here? We won't cover all the gory details, because the creators already [did](https://www.youtube.com/watch?v=uc1mbN9EJKQ). Instead we'll cautiously peek behind the curtain.

We'll use our trusty debugger, the [GEF-enhanced](https://gef.readthedocs.io/en/master/) `GDB` to gain more insights.

```txt { linenos=true, linenostart=1, hl_lines=["1"] }
$ gdb attach $(pidof guess)
fish: $(...) is not supported. In fish, please use '(pidof)'.
gdb attach $(pidof guess)
           ^
$ echo "So long, and thanks for all the fish"
So long, and thanks for all the fish
```

Now that we're attached, let's have a look at `rand()` before the instrumentation is applied:

```txt { linenos=true, linenostart=1, hl_lines=["5"] }
gef>  disass rand
Dump of assembler code for function rand:
   0x00007f6b04c587a0 <+0>:     endbr64
   0x00007f6b04c587a4 <+4>:     sub    rsp,0x8
   0x00007f6b04c587a8 <+8>:     call   0x7f6b04c58290 <random>
   0x00007f6b04c587ad <+13>:    add    rsp,0x8
   0x00007f6b04c587b1 <+17>:    ret
End of assembler dump.
```

`rand()` itself calls `random()`? Who would have [thought](https://sourceware.org/git/?p=glibc.git;a=blob_plain;f=stdlib/rand.c;hb=HEAD)?
Now let's inspect what happens _after_ we inject `Frida's` agent[^fn:3]:

```txt { linenos=true, linenostart=1, hl_lines=["3"] }
gef>  disass rand
Dump of assembler code for function rand:
   0x00007f6b04c587a0 <+0>:     jmp    0x7f6b0425e708
   0x00007f6b04c587a5 <+5>:     nop
   0x00007f6b04c587a6 <+6>:     nop
   0x00007f6b04c587a7 <+7>:     nop
   0x00007f6b04c587a8 <+8>:     call   0x7f6b04c58290 <random>
   0x00007f6b04c587ad <+13>:    add    rsp,0x8
   0x00007f6b04c587b1 <+17>:    ret
End of assembler dump.
```

Well, that `jmp` instruction certainly wasn't there before! But what's happening after we jump on this [trampoline](https://en.wikipedia.org/wiki/Trampoline_(computing))?

```txt { linenos=true, linenostart=1, hl_lines=["3","5"] }
gef>  x/7i 0x7f6b0425e708
   0x7f6b0425e708:      push   QWORD PTR [rip+0xfffffffffffffff2]        # 0x7f6b0425e700
   0x7f6b0425e70e:      jmp    0x7f6b0425e000
   0x7f6b0425e713:      push   QWORD PTR [rip+0xffffffffffffffe7]        # 0x7f6b0425e700
   0x7f6b0425e719:      jmp    0x7f6b0425e100
   0x7f6b0425e71e:      endbr64
   0x7f6b0425e722:      sub    rsp,0x8
   0x7f6b0425e726:      jmp    0x7f6b04c587a8 <rand+8>
```

Alright! Lines 6 and 7 are the ones that were replaced by the trampoline. The jump in the last line leads back to the correct point in the original function (which happens to be the `random()` call). This leaves us with the two magical jumps at line 3 and line 5 respectively.

Well, the magic lies on the other end of those jumps were the contents of the registers get saved and our JavaScript gets executed by the injected [QuickJS](https://bellard.org/quickjs/). But going even this deep is beyond the scope of this article[^fn:4], so let me again reference [this](https://www.youtube.com/watch?v=uc1mbN9EJKQ) great talk.

This concludes our very narrow introduction to `Frida`. Next we're going to look at something more practical...


### Twitch Plays {#twitch-plays}

Video games seem like a natural fit for things one wants to manipulate. It's already magical to press a button and things happen on screen, but what if we could have _n-levels_ of indirection and abstraction to practically achieve the same result?

So while searching for a lightweight "real world" use case (not your typical SSL Pinning Bypass[^fn:6]), I thought about instrumenting a `Game Boy` emulator in order to enable a [Twitch Plays](https://en.wikipedia.org/wiki/Twitch_Plays_Pok%C3%A9mon)-like interaction.

I've chosen `SameBoy` as the emulator, because it seems like a mature project and just works like a charm. Let's go ahead an grab a [copy](https://github.com/LIJI32/SameBoy) of the source code so that we can _grep_ around in it, shall we?

But before we fly through the codebase, let's take a step back and loosely define a scope so that we don't get lost. I think for now I'm content with remotely controlling the emulator. That means interactions with the internals of the "Game Boy" itself are out. Don't worry, there is `PyBoy` which comes equipped to [handle](https://github.com/Baekalfen/PyBoy/wiki/Scripts,-AI-and-Bots) such needs[^fn:7].


#### Reconnaissance {#reconnaissance}

How do we find those interesting places to hook into with `Frida`? Well, we simply reconnoiter[^fn:8] the codebase. There is an assumption we can safely make: An emulator, just like a video game itself, must have some sort of endless loop. In there input gets taken, states get updated and frames get rendered.

We could take a top-down approach by manually tracing the execution flow starting from `main()` until we find _something_ that handles key presses. Or we could `grep` for things like "input", "press", "release" and "key" and go from there.

But do you know what's even scarier than the endless loop of our _guess the number_ game? Approaching a large[^fn:9] `C` codebase by diving straight into its heart! So don't mind me slowly starting from the outset: `main()`. But where is it?

```txt { linenos=true, linenostart=1, hl_lines=["6"] }
$ grep -r -I "main("
Cocoa/GBGLShader.m:void main(void) {\n\
Cocoa/main.m:int main(int argc, const char * argv[])
Shaders/MasterShader.fsh:void main()
BootROMs/pb12.c:int main()
SDL/main.c:int main(int argc, char **argv)
SDL/shader.c:void main(void) {\n\
Tester/main.c:int main(int argc, char **argv)
```

And here I am, thinking every program has _one_ `main()` function. Because I was _told_ so! Let's see what we're dealing with:

```txt { linenos=true, linenostart=1 }
$ grep -r -I "main(" | wc -l
7
```

Weird flex but okay.

Apparently there are **seven** different `mains`. But the one file that sticks out is `SDL/main.c`. Like most, I know what `SDL` [is](https://www.libsdl.org/). But I've never used it. We'll have to learn as we go. We're fine.

Alright, we have our entry point, so let us begin.
To be clear, the following exploration is no detective work. We're simply cruising around in order to get inspired about possible `Frida`-attachment-points (_FAP_).

The start of `main()` sets up and configures a ton of things like the window, while eventually calling `run()`. Down there begins the actual emulation with the initialization of a struct representing the `Game Boy's` state. If we ever wanted to mess with the internals of the `Game Boy`, it would definitely involve this object, as a pointer to it is passed around the whole codebase. But at the moment we're only interested in the inputs, so let's continue.

At the end of `run()` we finally have our endless loop:

```c { linenos=true, linenostart=719, hl_lines=["5"] }
/* Run emulation */
while (true) {
    if (paused || rewind_paused) {
        SDL_WaitEvent(NULL);
        handle_events(&gb);
    }
    else {
        if (do_rewind) {
            GB_rewind_pop(&gb);
            if (turbo_down) {
                GB_rewind_pop(&gb);
            }
            if (!GB_rewind_pop(&gb)) {
                rewind_paused = true;
            }
            do_rewind = false;
        }
        GB_run(&gb);
    }

    /* These commands can't run in the handle_event function, because they're not safe in a vblank context. */
    if (handle_pending_command()) {
        pending_command = GB_SDL_NO_COMMAND;
        goto restart;
    }
    pending_command = GB_SDL_NO_COMMAND;
}
```

Immediately there's the `handle_events()` function that sticks out. This specific call site is locked behind some conditions, but using our editor of choice's _jump to references_ reveals a couple more. If we look inside, we get yet another `while` loop:

```c { linenos=true, linenostart=218, hl_lines=["4"] }
static void handle_events(GB_gameboy_t *gb)
{
    SDL_Event event;
    while (SDL_PollEvent(&event)) {
        switch (event.type) {
            case SDL_QUIT:
                pending_command = GB_SDL_QUIT_COMMAND;
                break;
// ... continues up to line 429.
```

Wow, that's a pretty big `switch` statement. The real interesting thing here is `SDL_PollEvent()`, though. I think it's time to read some documentation.

Being a good citizen, I first started using the `man-pages`. However, the ones for `SDL` (at least on my system) are from 2001\![^fn:10] Of _course_ I didn't realize this immediately. So let's spare us the pain and simply use the web and the codebase itself. Go ahead, grab [it](https://github.com/libsdl-org/SDL)!

The `SDL` project has a nice wiki where we find all the [information](https://wiki.libsdl.org/SDL_PollEvent) about `SDL_PollEvent()`. Its signature is `int SDL_PollEvent(SDL_Event* event)`. If there's an event in the queue, it will get stored in the `event` struct and the function returns 1. This explains the condition of the above `while` loop. It simply drains the queue until there are no events left. Further down the wiki page we can even see some example code that does this exact thing.

Now that we have a basic understanding of what's happening, let's take a closer look at the `switch` statement. What functions get called if the event corresponds to a key press?

Well, there's a _really_ scary case that handles `SDL_KEYDOWN` events that eventually falls through into the case that handles `SDL_KEYUP` events. So if all else fails, we end up in _that_ case, where we see this:

```c { linenos=true, linenostart=418, hl_lines=["4"] }
else {
    for (unsigned i = 0; i < GB_KEY_MAX; i++) {
        if (event.key.keysym.scancode == configuration.keys[i]) {
            GB_set_key_state(gb, i, event.type == SDL_KEYDOWN);
        }
    }
}
```

Alright, so we loop through every key, see if its [scancode](https://en.wikipedia.org/wiki/Scancode) matches a configured one[^fn:11] and finally call `GB_set_key_state()` in line 421. As mentioned before, we could end up here with either an `SDL_KEYDOWN`, or an `SDL_KEYUP` event. That's what the third argument is for: Is the key pressed or released?

Looking at it now, it's pretty basic stuff. But having never really took the time to read more `C` than your typical one-page examples, it was certainly a little adventure.

Now that we have discovered `GB_set_key_state()`, there's a new fork in the road: We could simply use `Frida` to get hold of a pointer to said function. The following example needs debug symbols, so we follow the project's [build instructions](https://github.com/LIJI32/SameBoy#compilation) to get a non-stripped version. Afterwards we can verify that it worked:

```txt { linenos=true, linenostart=1, hl_lines=["11","12"] }
(frida) $ frida sameboy
     ____
    / _  |   Frida 15.1.4 - A world-class dynamic instrumentation toolkit
   | (_| |
    > _  |   Commands:
   /_/ |_|       help      -> Displays the help system
   . . . .       object?   -> Display information about 'object'
   . . . .       exit/quit -> Exit
   . . . .
   . . . .   More info at https://frida.re/docs/home/
[Local::sameboy]-> DebugSymbol.getFunctionByName("GB_set_key_state")
"0x55b26b219860"
```

Yay, a pointer! This pointer could be used with `Frida`'s [NativeFunction API](https://frida.re/docs/javascript-api/#nativefunction), which would allow us to call `GB_set_key_state()` from `JavaScript`. However, we're not going to! Why not, you might ask? It seems simple enough!

While true, there's one major downside: **Threading**!

The first time I watched Ole's talks[^fn:5] about instrumenting `Quake`, I didn't quite understand why he wouldn't simply call "the shoot function". Instead, he opted to hold back until _just_ the right time. Why go the extra mile, though?
It turns out that `Frida` runs in its own thread in the target process. Well, of course it does. If we now start calling functions from this thread, we could disturb the work of other threads. Maybe we operate on some old state, or maybe the thing crashes. I honestly have no experience with threaded code to be certain.

But how do we make sure that we let the right thread do the work? Well, we pick a function that's likely a good target for being called by the right thread and do our work in there. That scenario screams for our trusty `Interceptor.attach()`, doesn't it?

It does! Ole did exactly that. So to recap:

-   `Frida` runs in its own thread
-   randomly calling things from it may cause some headaches
-   we somehow need to remember what to do / call
-   we use `Interceptor.attach()` to intercept a function that's likely executed by an appropriate thread
-   we do our work in there, which means the right thread does it

Uff, that sounds like a lot of work. But hold on! Didn't I talk about a fork? Well, what's the _other_ tine?

As we scrolled through the `SDL` wiki, we might have noticed the _related functions_ [section](https://wiki.libsdl.org/SDL_PollEvent#related_functions). Now `SDL_PushEvent()` sounds like a function we can relate to!
Its signature is `int SDL_PushEvent(SDL_Event* event)`. The documentation states the following:

```txt { linenos=true, linenostart=1, hl_lines=["8"] }
The event queue can actually be used as a two way communication channel. Not only can events be read from the queue,
but the user can also push their own events onto it.
event is a pointer to the event structure you wish to push onto the queue.
The event is copied into the queue, and the caller may dispose of the memory pointed to after SDL_PushEvent() returns.

Note: Pushing device input events onto the queue doesn't modify the state of the device within SDL.

This function is thread-safe, and can be called from other threads safely.
```

That's a bingo! We don't hook into `SameBoy's` code, but go directly to the source: The `SDL` event system. Because we can do _whatever_ we want!

We now enter serious `Frida` territory. So what's our plan? Firstly, we need a way to call native functions from our script. I briefly mentioned the `NativeFunction` API, so let's see what we can do with it:

```txt { linenos=true, linenostart=1, hl_lines=["13","15"] }
(frida) $ frida guess
     ____
    / _  |   Frida 15.1.4 - A world-class dynamic instrumentation toolkit
   | (_| |
    > _  |   Commands:
   /_/ |_|       help      -> Displays the help system
   . . . .       object?   -> Display information about 'object'
   . . . .       exit/quit -> Exit
   . . . .
   . . . .   More info at https://frida.re/docs/home/

[Local::guess]-> var putsAddr = Module.getExportByName(null, "puts")
[Local::guess]-> var nativePuts = new NativeFunction(putsAddr, "void", ["pointer"])
[Local::guess]-> var str = Memory.allocUtf8String("Hello World!")
[Local::guess]-> nativePuts(str)
```

Voila! Well, I cannot be bothered to make another screen cast for this little demo, so you simply have to _believe_ me. Or, you know, give it a try yourself.

In line 13, we create a new `NativeFunction` by providing an address (in the form of a `NativePointer`, obtainable because `puts` is a `libc` export), the return type and an array containing the arguments' types[^fn:12]. I specifically picked `puts()`, because its signature is so simple. But if you have higher demands like passing structs or classes by value (instead of just a pointer) or deal with [variadic functions](https://en.wikipedia.org/wiki/Variadic_function#In_C), `Frida` still got you covered!

In line 14 we let `Frida` do the allocation of our string and use the pointer to it as an argument for the `puts` wrapper in the next line. And then? The string gets printed into the `guess` output. **Amazing**, right? No no, I _mean_ it!

This is only the beginning, though. `Frida` helped us with allocating the string, but `SDL_PushEvent()` needs a pointer to an `SDL_Event`. Well, what is it exactly? The [documentation](https://wiki.libsdl.org/SDL_Event) states:

```txt { linenos=true, linenostart=1, hl_lines=["2"] }
The SDL_Event structure is the core of all event handling in SDL.
SDL_Event is a union of all event structures used in SDL.
Using it is a simple matter of knowing which event type corresponds to which union member.
The table below lists these relationships.
```

Alright, it's a union of all possible event structs. This means a variable with the `SDL_Event` type can hold _any_ event structure. Its size is therefore equal to the size of the _biggest_ event structure. Take for example the `SDL_KeyboardEvent`, this time directly from the `SDL` codebase (`SDL_Events.h`):

```c { linenos=true, linenostart=217, hl_lines=["6"] }
/**
 *  \brief Keyboard button event structure (event.key.*)
 */
typedef struct SDL_KeyboardEvent
{
    Uint32 type;        /**< ::SDL_KEYDOWN or ::SDL_KEYUP */
    Uint32 timestamp;   /**< In milliseconds, populated using SDL_GetTicks() */
    Uint32 windowID;    /**< The window with keyboard focus, if any */
    Uint8 state;        /**< ::SDL_PRESSED or ::SDL_RELEASED */
    Uint8 repeat;       /**< Non-zero if this is a key repeat */
    Uint8 padding2;
    Uint8 padding3;
    SDL_Keysym keysym;  /**< The key that was pressed or released */
} SDL_KeyboardEvent;
```

Because an `SDL_Event` could be _any_ event, we need a way to differentiate between them. That's what the `type` member is for. We saw it earlier in the `handle_events()` function, where it's used as the basis of the _humongous_ `switch` statement.

One more note before we continue: Different event _types_ can share the same event _structure_. Let's look at an example, taken from the wiki.

<div class="ox-hugo-table org-table">

| Event Type       | Event Structure   |
|------------------|-------------------|
| SDL_DROPFILE     | SDL_DropEvent     |
| SDL_DROPTEXT     | 〃                |
| SDL_DROPBEGIN    | 〃                |
| SDL_DROPCOMPLETE | 〃                |
| SDL_KEYDOWN      | SDL_KeyboardEvent |
| SDL_KEYUP        | 〃                |

</div>

Cool! So we built a bit of background knowledge. What do we do with it? Brag? No, we put it into practice!

Remember that we want to call `SDL_PushEvent()` from within our `Frida` script. As an argument, we need a pointer to an `SDL_Event`.
That's all great, but where do we actually _point_ to? We used `Memory.allocUtf8String()` before, but there's also the more generic `Memory.alloc()`. It takes the size as an argument and returns a pointer to the heap. The underlying memory gets freed once all handles to it are gone, so we have to keep that in mind.

Alright, we have a plan:

-   allocate some memory via `Frida`
-   craft a `SDL_KeyboardEvent` structure in that location
-   wrap `SDL_PushEvent()` into a `NativeFunction`
-   call said function with the pointer to our crafted event
-   cross fingers

I'm trying to remotely move Link in an emulator, but I feel like I'm planning a [sandbox escape](https://youtu.be/MMxtKq8UgwE?t=647). You've got to start somewhere, right?

Let's craft the struct. But what's the actual size of it? The definition from above gives us the sizes of all members, except for `SDL_Keysym`. We can find its definition in `SDL_keyboard.h`:

```C { linenos=true, linenostart=42, hl_lines=["8","9"] }
/**
 *  \brief The SDL keysym structure, used in key events.
 *
 *  \note  If you are looking for translated character input, see the ::SDL_TEXTINPUT event.
 */
typedef struct SDL_Keysym
{
    SDL_Scancode scancode;      /**< SDL physical key code - see ::SDL_Scancode for details */
    SDL_Keycode sym;            /**< SDL virtual key code - see ::SDL_Keycode for details */
    Uint16 mod;                 /**< current key modifiers */
    Uint32 unused;
} SDL_Keysym;
```

Let's continue with `SDL_Scancode` and `SDL_Keycode`.

`SDL_Scancode` has its own file, `SDL_scancode.h`. In there all available scancodes are part of an enum, with the maximal possible value of `512`. [Apparently](https://stackoverflow.com/a/366026) enums store their members as `ints`, but the compiler may optimize this behavior. Let's write a quick sanity check:

```C { linenos=true, linenostart=1 }
// enum.c
#include <stdio.h>
typedef enum {
    SDL_SCANCODE_UNKNOWN = 0,
    SDL_NUM_SCANCODES = 512,
} SDL_Scancode;

int main(void) {
    SDL_Scancode scancode = SDL_SCANCODE_UNKNOWN;
    printf("Size of scancode: %lu \n", sizeof(scancode));
    return 0;
}
```

```text
Size of scancode: 4
```

And `int` it is!

`SDL_Keycode` also has its own file (`SDL_keycode.h`) with an enum defining all the possible key codes. We'll skip over this and simply assume a size of 4 bytes, too.

Armed with all that knowledge, we _could_ go ahead and try to craft a `SDL_KEYDOWN` event. Let's back up for a moment, though.

Up to this point, we did the analysis statically. But wouldn't it be interesting to get some runtime information? We're using `Frida`, _A world-class dynamic instrumentation toolkit_, after all!

We're going to use `Interceptor.attach()` to hook into `SDL_PollEvent()`, check if it actually polled one and in case it _did_ try to parse it:

```js { linenos=true, linenostart=1, hl_lines=["25","31"] }
// parse.js
const pollEventAddr = Module.getExportByName(null, "SDL_PollEvent");

const parseEvent = (eventPtr) => {
    console.log("====================================================");
    console.log("type: 0x" + eventPtr.readU32().toString(16));
    console.log("timestamp: " + eventPtr.add("0x4").readU32().toString());
    console.log("windowId: " + eventPtr.add("0x8").readU32().toString());
    console.log("state: " + eventPtr.add("0xC").readU8().toString());
    console.log("repeat: " + eventPtr.add("0xD").readU8().toString());
    console.log("padding2: " + eventPtr.add("0xE").readU8().toString());
    console.log("padding3: " + eventPtr.add("0xF").readU8().toString());
    console.log("-----------------SDL_Keysym struct------------------");
    console.log("scancode: 0x" + eventPtr.add("0x10").readU32().toString(16));
    console.log("sym: 0x" + eventPtr.add("0x14").readS32().toString(16));
    console.log("mod: 0x" +  eventPtr.add("0x18").readU16().toString(16));
    console.log("unused: " + eventPtr.add("0x1A").readU32().toString());
    console.log("----------------------------------------------------");
    console.log("====================================================");
    console.log("\n");
}

Interceptor.attach(pollEventAddr, {
    onEnter: function(args) {
        this.SDLEvent = args[0];
    },
    onLeave: function(retVal) {
        // This returns 1 if an event was taken from the queue.
        // See the SDL documentation for more details.
        if (!retVal.isNull()) {
            const eventPtr = ptr(this.SDLEvent);

            // Only parse SDL_KEYDOWN and SDL_KEYUP events.
            const eventType = "0x" + eventPtr.readU32().toString(16);
            if (eventType === "0x301" || eventType === "0x300") {
                parseEvent(eventPtr);
            }
        }
    }
})
```

There's a lot to discuss here. As usual, we get the address of our target function in order to use it as an argument for `Interceptor.attach()`. It gets interesting in line 25, though.

Remember that `SDL_PollEvent()` takes a pointer to an empty `SDL_Event` struct in order to populate it with values. We can get hold of said pointer with `args[0]`, because it's the first (and only) parameter.
But as I said, the structure is uninitialized! The function has to do its thing before we see any results. So `Frida's` `onLeave()` callback is the right place to inspect the _populated_ struct, right? Well, almost!

There's a problem: We only have access to the return value. The function, however, doesn't return the struct _itself_, but a status code indicating if an event was taken from the queue. But `Frida` has got our back, _again_!

As we can see in line 25, we are able to store arbitrary data via the `this` keyword[^fn:13]. Let's go ahead and save our pointer, so that we can check it again _after_ `SDL_PollEvent()` populated the fields. We only want to take action if an event was taken from the queue, so we check if the return value is not `0` in line 30.

Furthermore we're only interested in `SDL_KEYUP` and `SDL_KEYDOWN` events, so we check the type field that all event structs have in common. Where can we find that information? `SDL_events.h` contains the `SDL_EventType` enum:

```C { linenos=true, linenostart=96, hl_lines=["3","4"] }
//----snip----
    /* Keyboard events */
    SDL_KEYDOWN        = 0x300, /**< Key pressed */
    SDL_KEYUP,                  /**< Key released */
    SDL_TEXTEDITING,            /**< Keyboard text editing (composition) */
    SDL_TEXTINPUT,              /**< Keyboard text input */
    SDL_KEYMAPCHANGED,          /**< Keymap changed due to a system event such as an
                                     input language or keyboard layout change.
                                */
//----snip----
```

So we're looking for types `0x300` and `0x301`. Now let's actually parse the events. Our script's `parseEvent()` function uses the base pointer of the struct, adds data type appropriate offsets and `Frida's` built-in `NativePointer.read*()` functions to get the values. Those functions will automatically deal with endianess[^fn:14]. It's not pretty, but we're still in our discovery phase.

Does this work?

<video controls preload="metadata"><source src="/frida-sdl-event-parse.mp4" type="video/mp4">
Your browser does not support the video tag.</video>

Yes it does! We could verify by checking the scancodes in `SDL_scancode.h`. But you know me. I already _did_.

(•_•)

( •_•)&gt;⌐◼-◼

(⌐◼_◼)


#### Get a move on {#get-a-move-on}

Now it's time to **get moving**! To make our life easier, let's have a quick look at the raw bytes of a left press. We can use `Frida's` `NativePointer.readByteArray()` to get the contents and simply print them with `console.log()`. With a length of 30, we get the following result:

```txt { linenos=true, linenostart=1, hl_lines=["2","6"] }
           0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF
00000000  00 03 00 00 8b 6f 02 00 02 00 00 00 01 01 00 00  .....o..........
00000010  50 00 00 00 50 00 00 40 00 00 b5 3c fc 7f        P...P..@...<..

           0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF
00000000  01 03 00 00 ad 6f 02 00 02 00 00 00 00 00 00 00  .....o..........
00000010  50 00 00 00 50 00 00 40 00 00 fd 3b bf 53        P...P..@...;.S
```

We're looking at a press in line 2 (`00 03`) and a release in line 6 (`01 03`) of the left arrow key (`00 00 00 50`). The left arrow is defined as `SDL_SCANCODE_LEFT = 80`, so we're good[^fn:15].

Before we build some fancy abstractions, let's quickly verify that we're onto something with our approach. We'll keep it down-to-earth by taking the two event structs from above and pushing them to `SDL's` queue.

```js { linenos=true, linenostart=1 }
// telecontrol.js

function sleep(milliseconds) {
 return new Promise(resolve => setTimeout(resolve, milliseconds));
}

// Get the address of our target function.
const pushEventAddr = Module.getExportByName(null, "SDL_PushEvent");

// Wrap it inside a *NativeFunction* so that we can call it from here.
const pushEvent = new NativeFunction(pushEventAddr, "int", ["pointer"]);

// Raw bytes of a left press.
const leftPress = [
    0x00, 0x03, 0x00, 0x00, 0x8b, 0x6f, 0x02, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00,
    0x00, 0x50, 0x00, 0x00, 0x00, 0x50, 0x00, 0x00, 0x40, 0x00, 0x00, 0xb5, 0x3c, 0xfc, 0x7f,
]

// Raw bytes of a left release.
const leftRelease = [
    0x01, 0x03, 0x00, 0x00, 0xad, 0x6f, 0x02, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x50, 0x00, 0x00, 0x00, 0x50, 0x00, 0x00, 0x40, 0x00, 0x00, 0xfd, 0x3b, 0xbf, 0x53,
]

// Allocate space on on the heap for one press and one release event.
const fakePressPtr = Memory.alloc(30);
const fakeReleasePtr = Memory.alloc(30);

// Write our event bytes into heap memory.
fakePressPtr.writeByteArray(leftPress);
fakeReleasePtr.writeByteArray(leftRelease);

// This functions is callable from the Frida REPL.
const pressLeft = async function() {
    // Call *SDL_PushEvent()*. The argument is the pointer
    // inside the heap, where our fake press event resides.
    pushEvent(fakePressPtr);

    // Sleep for a bit so that things get registered correctly.
    await sleep(100);

    // Push our fake release event.
    pushEvent(fakeReleasePtr);
}
```

Can we get away with it?

<video controls preload="metadata"><source src="/frida-push-left.mp4" type="video/mp4">
Your browser does not support the video tag.</video>

No [Bill](https://en.wikipedia.org/wiki/Operation_C_(video_game)#Plot), what are you doing? You're in a Game Boy game from 1991, not in some convention breaking indie game! You can't go left, there's nothing there! You _always_ go right, stupid!

Anyway, we _got_ away with it. The attentive reader may have noticed that we also reused the timestamps. It simply didn't matter. In fact, we could just zero out the bytes and we'd still be fine. Why, you might ask? Well, we get our answer in `SDL_events.c`:

```c { linenos=true, linenostart=963, hl_lines=["4"] }
int
SDL_PushEvent(SDL_Event * event)
{
    event->common.timestamp = SDL_GetTicks();
// ----snip----
```

Okay, okay, I'm going to stop with the code analysis. It's just so much fun to get to the bottom of things. Maybe not _rock bottom_...

Now we're almost done here. Let's create a more fleshed out final implementation of our idea. We want to be able to remotely "press" any of the relevant buttons.

We need a bit more ceremony to make it work. The following example uses _TypeScript_ (as suggested by the `Frida` docs). This comes with a lot of benefits like code completion, inline docs and - who would have guessed - _type checking_! But don't worry, we just define a couple of types to make things more readable. Nothing too fancy!

```js { linenos=true, linenostart=1, hl_lines=["62"] }
// telecontrol.ts
import * as http from "http";

// Standard duration of a keypress in milliseconds.
const STD_DURATION = 100;

enum ScanCode {
    Z = 29,
    X = 27,
    RETURN= 40,
    BACKSPACE= 42,
    RIGHT = 79,
    LEFT = 80,
    DOWN = 81,
    UP = 82,
}

enum EventType {
    KEYDOWN = 0x300,
    KEYUP = 0x301,
}

interface CommandDictionary {
    [index: string]: ScanCode;
}

const commandDictionary: CommandDictionary = {
    b: ScanCode.Z,
    a: ScanCode.X,
    start: ScanCode.RETURN,
    select: ScanCode.BACKSPACE,
    right: ScanCode.RIGHT,
    left: ScanCode.LEFT,
    down: ScanCode.DOWN,
    up: ScanCode.UP,
}

const sleep = (milliseconds: number): Promise<void> => {
    return new Promise(resolve => setTimeout(resolve, milliseconds));
}

const pushEventAddr = Module.getExportByName(null, "SDL_PushEvent");
const pushEvent = new NativeFunction(pushEventAddr, "int", ["pointer"]);

const createEvent = async (scancode: ScanCode, duration: number) => {
    // We shouldn't need to zero out the array, but just in case.
    const eventPointer = Memory.alloc(30).writeByteArray(new Array(30).fill(0));

    eventPointer.writeU32(EventType.KEYDOWN);
    eventPointer.add("0x10").writeU32(scancode);
    pushEvent(eventPointer);

    // "Hold" down the button.
    await sleep(duration % 2001)

    // We only need to change the event type.
    eventPointer.writeU32(EventType.KEYUP);
    pushEvent(eventPointer);
}

// The functions inside this object will be magically available from outside.
rpc.exports = {
    startServer: function() {
        http.createServer(async (req, res) => {

            const fullCommand = req.url ? req.url.replace("/", "") : "";
            // We allow commands in the form "left:2000", split them at the colon
            // and destructure the array returned by the split() method.
            const [command, duration] = fullCommand.split(":");

            const scanCode = commandDictionary[command];

            if (!scanCode) {
                res.statusCode = 400;
                res.write("Wrong command")
            } else {
                let parsed = parseInt(duration, 10);
                parsed = (isNaN(parsed)) ? STD_DURATION : parsed;

                createEvent(scanCode, parsed);

                res.statusCode = 200;
                res.write(command + " " + duration);
            }

            res.end();
        }).listen(1337);
        console.log("[+] Successfully started server on port 1337");
    }
};
```

The code is commented, but there are a few things that I want to highlight. That I _did_ highlight!
In line 62 we define the `startServer` method inside the `rpc.exports` object. Every method of said object gets exposed to the outside, meaning we can _consume_ them from all the available `Frida` bindings. We'll get there in a second. But first let's take that second and appreciate the fact that we are able to **start a HTTP server inside our target process**! It just never gets old...

We're not doing it _just_ for the lulz, though. I'm really, really tired and don't want to implement the whole "Twitch Plays" concept end-to-end. The HTTP server is just a convenient way to get commands inside our agent in order to test the core functionality.

Because we also allow the duration of the button press to be specified, things like holding up the shield in _Link's Awakening_ are possible.

Onwards with the whole ceremony: We're going to consume the exported function from the `Python` bindings, so let's have a quick look at the script:

```python { linenos=true, linenostart=1, hl_lines=["5","6","13"] }
# sameboy.py
import frida
import sys

with open("telecontrol.js") as f:
    agent = f.read()

session = frida.attach("sameboy")
script = session.create_script(agent)
script.load()

# Call our exported script, which in turn starts the HTTP server.
script.exports.start_server()

# Do something that blocks the script from exiting.
sys.stdin.readline()
```

What's happening? Well, in line 5 and 6 we read the contents of our `JavaScript` file. Wait a second, _JavaScript_? Didn't we write our agent in _TypeScript_?

Yes, we did. But `Frida` doesn't deal with `TS` directly, so we had to compile it. There's [this](https://github.com/oleavr/frida-agent-example) (official) example project, which makes the process friction less[^fn:17].
In line 13 we call the exported function, which internally starts the `HTTP` server. Notice that we originally called the method `startServer` (in camelCase). `Frida` is all about that sweet [pythonicness](https://www.python.org/dev/peps/pep-0008/#function-and-variable-names), so it converted the name for us.

Did all that hard work pay off?

<video controls preload="metadata"><source src="/frida-move-link.mp4" type="video/mp4">
Your browser does not support the video tag.</video>

Hoot! Hoot!

We actually did it. We moved Link. I'm almost a little moved myself.


#### Outlook {#outlook}

Now that we're done with the core functionality, let's think about what's _missing_ before we could get a "Twitch Plays" session started.

First of all, we want to receive our commands from the chat, so we have to integrate with the Twitch API. We can have a look at the [documentation](https://dev.twitch.tv/docs/irc) to get an idea how that might work. Looks doable, doesn't it?

Knowing that there's a `JavaScript` [package](https://tmijs.com/) for dealing with the chat, I'd suggest skipping over `Python` in favor of the `Node.js` [bindings](https://github.com/frida/frida-node). That way everything is neatly contained in one (hell of an) ecosystem.

Finally there needs the be some form of throttling and filtering. Because trolls keep trolling!

Still looks doable, doesn't it? I should put my money where my mouth is[^fn:16], but I won't. Not this time, anyway, so deal with it!


### Conclusion {#conclusion}

Uff, what a ride! Let's recap:

We used `Frida` to inject a `JavaScript` agent into a target process. In the first example, we only _intercepted_ calls that were already present in the program. By manipulating the return value of a library function, we changed its behavior _dynamically_.

Afterwards we did a tiny bit of code auditing in order to discover a good point for hooking into `SameBoy` so that we can remotely send input commands. We discovered that the `SDL` library is a great place for that.

A quick aside here:

The high-level approach taken by some "Twitch Plays" implementations is to send input via tools like [xdotool](https://www.semicomplete.com/projects/xdotool/), which covers a broader range of possible emulators and games, because they are not dependent on `SDL` being available. This approach comes with its own hurdles, though. It might not be portable across operating systems and things like window focus could come into play.

The low-level approach would be to just manipulate `SameBoy` directly. Somewhere the state of the buttons is tracked. I'm confident that we could reach it with `Frida`! While certainly a fun discovery process, this approach is the least generic and portable. And it doesn't prove the point I'm about to make.

We sit comfortably in the middle: In theory, every `SDL` project gets covered. Which are a lot (e.g. the wonderful [PICO-8](https://www.lexaloffle.com/pico-8.php))! I haven't tested this yet, but with some tweaks, our approach could surely work with those.

Asides aside, after discovering the `SDL_PushEvent()` function, we looked into how we could call it from our script in order to push _our_ events into the `SDL` event queue. Reading more of the source gave us the right format. We confirmed our theory by intercepting the legitimate events, again thanks to `Frida`.

In our final version we allocate a buffer on the heap, craft an event structure in there and call `SDL_PushEvent()` with a pointer to it.

I cannot overstate how cool that is! `Frida` let us interact with code that's not even _used_ by `SameBoy`. It just goes to show how much **stuff** actually is inside our programs (runtime, libraries etc.).

Code reuse attacks like [return-to-libc](https://en.wikipedia.org/wiki/Return-to-libc_attack) and more "recently" [return-oriented programming](https://en.wikipedia.org/wiki/Return-oriented_programming) are exploiting this very fact[^fn:18]. Those attacks are just _extremely_ fascinating. I'm looking forward to cover them in some future articles.

And just like that, we're done! I'm sure the information in this article could have been more condensed. But as I mentioned in the introduction, I've tried to make the process of discovery as visible as I possible can without _really_ being boring. Personally, I do enjoy articles that highlight the journey. If I only get an end result, the topic often seems too intimidating. Hopefully you won't feel this way about `Frida` after reading this far. Thank you!


### Resources and Acknowledgments {#resources-and-acknowledgments}

-   Leon Jacob's [frida-boot](https://www.youtube.com/watch?v=CLpW1tZCblo) workshop (Thanks for letting me hit the ground running!)
-   Ole's talks mentioned in footnote `5` (Demo time? Every presentation is just a _single_ take. What now, _demo gods_?)
-   Game hacking with `Frida` by [X-C3LL](https://twitter.com/TheXC3LL) (A really playful introduction.)
-   A talk about `Frida's` [architecture](https://www.youtube.com/watch?v=uc1mbN9EJKQ)
-   A couple of older [presentations](https://frida.re/docs/presentations/) from `Frida's` website

Thanks to all people who contributed to `Frida`, first and foremost to Ole. I'm really grateful for being able to use something which must have taken a _lot_ of time to make!

[^fn:1]: Thanks Al for teaching me how to program! I mean it.
[^fn:2]: Why 1? Because our code specifies the valid range like so: `(rand() % 10) + 1`
[^fn:3]: I had to detach `GDB` from the process in order for `Frida` to be able to inject its agent into it.
[^fn:4]: And beyond my current knowledge to be honest.
[^fn:5]: The author of `Frida` himself somehow managed to smuggle _Quake_ into a _NDC_ [talk](https://www.youtube.com/watch?v=LoJcXmBxIos) about testing. And [again](https://www.youtube.com/watch?v=HB_wfa1F31o)! What a guy :).
[^fn:6]: Maybe the one thing that `Frida` is most known for.
[^fn:7]: With some amazing [results](https://towardsdatascience.com/beating-the-world-record-in-tetris-gb-with-genetics-algorithm-6c0b2f5ace9b)!
[^fn:8]: You live and learn :).
[^fn:9]: I actually don't know if it's a big project. Running `cloc` on the project's `Core` directory suggest a cool 14866 lines of code. The complete repository comes in at 47272 lines. That's big in my book.
[^fn:10]: "Tue 11 Sep 2001, 22:59" to be precise. I can't think of a better way to relax after a _stressful_ day than to write documentation ¯\\_(ツ)\_/¯.
[^fn:11]: `SameBoy` supports button remapping, so we have a layer of indirection here.
[^fn:12]: When in doubt, just check the respective man-page.
[^fn:13]: I have no `JavaScript` PhD, but I think [this](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Operators/this#as_an_object_method) (hihihi) explains why we can't use arrow functions for `onEnter()` and `onLeave()`
[^fn:14]: `SDL_KEYUP` takes 4 bytes, which looks like this on my x86-64 little-endian machine: **01 03 00 00**
[^fn:15]: `80` in decimal is `50` in hex.
[^fn:16]: In other words: [PoC||GTFO](https://nostarch.com/gtfo)
[^fn:17]: That is, if you know your way around the `TS` / `JS` ecosystem at least a tiny bit.
[^fn:18]: In the case of `ROP` we can construct functionality that's not even present _at all_!
