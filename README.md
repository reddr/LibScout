# LibScout

LibScout is a light-weight and effective static analysis tool to detect third-party libraries in Android apps. The detection is resilient against<br>
common bytecode obfuscation techniques such as identifier renaming or code-based obfuscations such as reflection-based API hiding or control-flow randomization.<br>
LibScout requires the original library SDKs (compiled .jar/.aar files) to extract library profiles that can be used for detection on Android apps.

Unique features:
 * Library detection resilient against many kinds of bytecode obfuscation
 * Capability of pinpointing the exact library version (in some cases to a set of 2-3 candidate versions)
 * Capability of handling dead-code elimination, by computing a similarity score against baseline SDKs

For technical details and large-scale evaluation results, please refer to our publication:<br>
> Reliable Third-Party Library Detection in Android and its Security Applications<br>
> https://www.infsec.cs.uni-saarland.de/~derr/publications/pdfs/derr_ccs16.pdf

For comments, feedback, etc. contact:  Erik Derr  [lastname@cs.uni-saarland.de]



##   LibScout Repo Structure
<pre><code>
|_ build.xml (ant build file to generate runnable .jar)
|_ data
|    |_ library-data.sqlite (library meta data)
|    |_ library-profiles.zip (all library profiles)
|    |_ app-version-codes.csv (app packages with valid version codes)
|_ lib
|    pre-compiled WALA libs, Apache commons*, log4j, Android SDK 
|_ logging
|    |_ logback.xml (log4j configuration file)
|_ scripts
|    |_ mvn-central
|         |_ mvn-central-crawler.py (script to retrieve complete library histories from mvn-central)
|_ src
    source directory of LibScout (de/infsec/tpl). Includes some open-source,
    third-party code to parse AXML resources / app manifests etc.
</code></pre>


##   Getting Started

<ol>
<li>LibScout requires Java 1.7 or higher. If you're using OpenJDK you need to use either 1.7 <b>or</b> 1.9 (1.8 seems to have some strange bytecode verification bug)<br>
   A runnable jar can be generated with the build.xml</li>
<li>LibScout has three modes of operation:<br>
    <ol type="a">
        <li>    
            Generate library profiles from original library SDKs:<br>
            <pre>java -jar LibScout.jar -x &lt;$lib-dir/library.xml&gt; -a &lt;lib/android-X.jar&gt; &lt;$lib-dir/lib.jar&gt; </pre>
        </li>
        <li>
            Detect libraries in apps using pre-generated profiles:<br>
            <pre>java -jar LibScout.jar -a lib/android-X.jar -p &lt;$path-to-lib-profiles&gt; -d &lt;$log-dir&gt; someapp.apk  </pre>
        </li>
        <li>
            Generate a SQLite database from library profiles and serialized app stats:<br>
            <pre>java -jar LibScout.jar -a &lt;lib/android-X.jar&gt; -p &lt;$path-to-lib-profiles&gt; -db &lt;$path-to-app-stats&gt; someapp.apk </pre>
        </li>
    </ol>
</li>
<li>
 Some classes to start with:
 <ul>
   <li><b>de.infsec.tpl.TplCLI</b>: &nbsp;&nbsp;  Starting class including CLI parsing and logging init</li>
   <li><b>de.infsec.tpl.LibraryHandler</b>:&nbsp;&nbsp;  Starting class to extract library profiles</li>
   <li><b>de.infsec.tpl.LibraryIdentifier</b>:&nbsp;&nbsp;  Code to match lib profiles and application bytecode</li>
   <li><b>de.infsec.tpl.hash.HashTree</b>:&nbsp;&nbsp;  main data structures used for profiles</li>
</li>
<li><i>How to aggregate per-app results during large-scale evaluation?</i><br>
   While the tool consumes one app at a time, it can serialize the app results to disk. Using
   operation mode c), LibScout loads all app results to generate one convenient SQLite file<br>
   (the DB structure can be found in class de.infsec.tpl.stats.SQLStats)
</li>
</ol>




##   Library Profiles

While we can not make the original library SDks publicly available for legal reasons, we provide the following:<br>
<ul>
 <li>all library profiles (ready-to-use for detection in apps)&nbsp;&nbsp; [data/library-profiles.zip]</li>
 <li>an accompanying SQLite DB with parsed library data (name, version, release date, ..)&nbsp;&nbsp;  [data/library-data.sqlite]</li>
 <li>a python script to automatically download complete version histories from maven-central
   incl. config script&nbsp;&nbsp; [scripts/mvn-central/mvn-central-crawler.py]</li>
</ul>
