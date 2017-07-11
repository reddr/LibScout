# LibScout

LibScout is a light-weight and effective static analysis tool to detect third-party libraries in Android apps. The detection is resilient against common bytecode obfuscation techniques such as identifier renaming or code-based obfuscations such as reflection-based API hiding or control-flow randomization.<br>
LibScout requires the original library SDKs (compiled .jar/.aar files) to extract library profiles that can be used for detection on Android apps.

Unique features:
 * Library detection resilient against many kinds of bytecode obfuscation
 * Capability of pinpointing the exact library version (in some cases to a set of 2-3 candidate versions)
 * Capability of handling dead-code elimination, by computing a similarity score against baseline SDKs

For technical details and large-scale evaluation results, please refer to our publication:<br>
> Reliable Third-Party Library Detection in Android and its Security Applications<br>
> https://www.infsec.cs.uni-saarland.de/~derr/publications/pdfs/derr_ccs16.pdf

If you use LibScout in a scientific publication, we would appreciate citations using this Bibtex entry: [[bib]](https://www.infsec.cs.uni-saarland.de/~derr/publications/bib/derr_ccs16.bib)<br>


##   Library Profiles and Scripts

To facilitate usage of LibScout we are happy to release our datasets to the community. <br>
You can find the following resources in the data/scripts directory:<br>


### Library Profiles (last updated:  06/27/2017)

You can find all <b>library profiles</b> (ready-to-use) for lib detection in apps in the data directory as compressed .zip file.<br>
It currently includes <b>205</b> unique libraries and <b>3,071</b> library versions.<br> For convenience, data/library-data.csv contains a complete list of library/-versions including meta data such as release dates.

### Scripts (scripts/mvn-central)
The scripts directory further contains a python script to automatically download original library SDKs including complete version histories from maven-central.<br>
The set of libraries we currently retrieve is stored in a json file.<br>


Due to copyright reasons we cannot publicy provide the original library SDKs. If you are interested in this data, send us an email.
We also welcome contributions to LibScout or our library database (either original SDKs or scripts for automatic retrieval from sources other than mvn central).<br><br>
Contact us for comments, feedback, how to contribute:  Erik Derr  [lastname@cs.uni-saarland.de]


## Detecting vulnerable library versions

LibScout has builtin functionality to report library versions with the following security vulnerabilities.<br>
Detected vulnerable versions are tagged with <b>[SECURITY]</b>, patches with <b>[SECURITY-FIX]</b>. <br>
This information is encoded in the library.xml files that have been used to generate the profiles.
We try to update the list/profiles whenever we encounter new security issues. If you can share information, please let us know.


| Library    |   Version(s)    | Fix Version   |  Vulnerability                         |     Link  |
| ---------- | ---------------:|--------------:|--------------------------------------- | ---------------------------------------------------------------------------------------------------------------   |
| Airpush    |      < 8.1      |  > 8.1        |  Unsanitized default WebView settings  |  [Link](https://support.google.com/faqs/answer/6376737)  |
| Apache CC  | 3.2.1 / 4.0     |  3.2.2 / 4.1  |  Deserialization vulnerability         |  [Link](http://www.kb.cert.org/vuls/id/576313)  |
| Dropbox    | 1.5.4 - 1.6.1   |   1.6.2       |  DroppedIn vulnerability               |  [Link](https://blogs.dropbox.com/developers/2015/03/security-bug-resolved-in-the-dropbox-sdks-for-android)  |
| Facebook   |       3.15      |    3.16       |  Account hijacking vulnerability       |  [Link](http://thehackernews.com/2014/07/facebook-sdk-vulnerability-puts.html)  |
| MoPub      |    < 4.4.0      |  4.4.0        |  Unsanitized default WebView settings  |  [Link](https://support.google.com/faqs/answer/6345928)  |
| OkHttp     | 2.1-2.7.4 / 3.0.0-3.1.2  |  2.7.5 / 3.2.0 |  Certificate pinning bypass  |  [Link](https://medium.com/square-corner-blog/vulnerability-in-okhttps-certificate-pinner-2a7326ad073b)  |
| SuperSonic |    < 6.3.5      |   6.3.5       |  Unsafe functionality exposure via JS  |  [Link](https://support.google.com/faqs/answer/7126517)  |
| Vungle     |    < 3.3.0      |  3.3.0        |  MitM attack vulnerability             |  [Link](https://support.google.com/faqs/answer/6313713)  |


On our last scan of free apps on Google Play (05/25/2017), LibScout detected >20k apps containing one of these vulnerable lib versions.
These results have been reported to Google's [ASI program](https://developer.android.com/google/play/asi.html) (still under investigation).


##   LibScout Repo Structure
<pre><code>
|_ build.xml (ant build file to generate runnable .jar)
|_ data (library profiles and supplemental data sets)
|    |_ library-data.csv (library meta data)
|    |_ library-profiles-21.06.zip (all library profiles)
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
<li>LibScout requires Java 1.8 or higher. A runnable jar can be generated with the ant script <i>build.xml</i></li>
<li><b>Modes of operation (provided via -o switch):</b><br>
    Profile and Match mode require an Android SDK, provided via the -a switch, to distinguish app code from framework code.<br>
    For your convenience, you can use the one provided in the lib directory.
    <ol type="a">
        <li>
            Library Profiling (-o profile)<br>
            Generate library profiles from original library SDKs (.jar and .aar files supported). Besides the library file, this mode requires a library.xml that
            contains some meta-data about the library (e.g. name, version, etc.). A library.xml template can be found in the assets directory. Use the -v switch to generate trace profiles,
            i.e. profiles with class and method signatures, where methods are limited to public methods (Trace profiles are required as input for the library api analysis):<br>
            <pre>java -jar LibScout.jar -o profile -a lib/android-X.jar -x ${lib-dir/library.xml} ${lib-dir/lib.[jar|aar]} </pre>
        </li>
        <li>
            Library Matching (-o match)<br>
            Detect libraries in apps using pre-generated profiles (this example logs to directory + serializes results):<br>
            <pre>java -jar LibScout.jar -o match -a lib/android-X.jar -p &lt;path-to-lib-profiles&gt; -s -d &lt;log-dir&gt; $someapp.apk  </pre>
        </li>
        <li>
            Database creation (-o db)<br>
            Generate a SQLite database from library profiles and serialized app stats:<br>
            <pre>java -jar LibScout.jar -o db -p &lt;path-to-lib-profiles&gt; -s &lt;path-to-app-stats&gt; </pre>
        </li>
        <li>
            Library API robustness analysis (-o lib_api_analysis)<br>
            Analyzes changes in the set of library APIs across versions (additions/removals/modifcations). Checks for <a href="http://semver.org">SemVer</a> compliance, i.e. whether the change in the version string matches
            the changes in the public API set. SemVer compliance statistics are logged, while API robustness data is written out in JSON format (use -j switch to configure).
            If you use this mode you have to provide trace profiles (generated via -o profile -v).<br>    
            <pre>java -jar LibScout.jar -o lib_api_analysis -p &lt;path-to-lib-profiles&gt; -j &lt;json-output-path&gt; </pre>
        </li>
    </ol>
</li>
<li><b>Output formats:</b> There are three different output formats available (individually configurable).
    <ol type="a">
        <li>
            <b>Textual logging</b>. Per default, LibScout logs to stdout. Use the -d switch to redirect output to files. The -m switch disables any text output.
        </li>
        <li>
            <b>JSON</b> output can be enabled via -j switch.
        </li>
        <li>
            The analysis results per app can also be <b>serialized</b> to disk using the -s switch. This is particularly useful for large-scale evaluations.
            After all apps have been processed, you can use operation mode c) to generate one convenient SQLite file from the serialized results
            (the DB structure can be found in class de.infsec.tpl.stats.SQLStats).
        </li>
    </ol>
</li>
<li>
    If you are interested in digging into the source, here are some classes to start with:
    <ul>
      <li><b>de.infsec.tpl.TplCLI</b>: &nbsp;&nbsp;  Starting class including CLI parsing and logging init</li>
      <li><b>de.infsec.tpl.LibraryProfiler</b>:&nbsp;&nbsp;  Starting class to extract library profiles</li>
      <li><b>de.infsec.tpl.LibraryIdentifier</b>:&nbsp;&nbsp;  Code to match lib profiles and application bytecode</li>
      <li><b>de.infsec.tpl.hash.HashTree</b>:&nbsp;&nbsp;  main data structures used for profiles</li>
    </ul>
</li>

</ol>
