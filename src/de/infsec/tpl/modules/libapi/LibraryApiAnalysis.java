package de.infsec.tpl.modules.libapi;


import com.ibm.wala.classLoader.IMethod;

import com.ibm.wala.ipa.callgraph.AnalysisScope;
import com.ibm.wala.ipa.cha.ClassHierarchy;
import com.ibm.wala.ipa.cha.ClassHierarchyException;
import com.ibm.wala.ipa.cha.IClassHierarchy;
import com.ibm.wala.types.ClassLoaderReference;
import de.infsec.tpl.TplCLI;
import de.infsec.tpl.profile.LibraryDescription;
import de.infsec.tpl.utils.AarFile;
import de.infsec.tpl.utils.Utils;
import de.infsec.tpl.xml.XMLParser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.util.*;
import java.util.jar.JarFile;


/**
 * = Library API Analysis =
 *
 * - Extracts the public (documented) API from original library code packages
 * - Checks API stability across versions for the same library (expected/actual semantic versioning)
 * - Searches for API alternatives in case of removed APIs
 * - Results of type {@link LibApiStats.Export} are written to {@link TplCLI.CliArgs#ARG_JSON_DIR}
 */

public class LibraryApiAnalysis {
    private static final Logger logger = LoggerFactory.getLogger(LibraryApiAnalysis.class);

    // Mapping from <path to library.xml> -> <path to lib.(jar|aar)>
    private Map<File,File> meta2Code = new HashMap<File,File>();

    private Map<String, LibApiStats> libName2Stats = new HashMap<String, LibApiStats>();


    public LibraryApiAnalysis(File libDir) {
        locateLibrarySDKs(libDir);
        parseLibrarySDKs(true);

        analyzeLibraryAPIs();
    }


    private void analyzeLibraryAPIs() {
        LibApiComparator comp = new LibApiComparator();
        for (LibApiStats lib: libName2Stats.values()) {
            logger.info("Process library: " + lib.libName);
            lib.version2Diff = comp.run(lib);

            // write to disk
            writeLibData(lib);
        }
    }


    private void writeLibData(LibApiStats stats) {
        // output results in json format
        File jsonOutputFile = new File(TplCLI.CliOptions.jsonDir + File.separator + "libApis" + File.separator + stats.libName + ".json");

        try {
            Utils.obj2JsonFile(jsonOutputFile, stats.export());
            logger.info("Results for library: " + stats.libName + " written to " + jsonOutputFile);
        } catch (IOException e) {
            logger.warn("Could not write json results: " + Utils.stacktrace2Str(e));
        }
    }


    private void parseLibrarySDKs(boolean skipBeta) {
        for (File libXML : meta2Code.keySet()) {
            try {
                LibraryDescription ld = XMLParser.readLibraryXML(libXML);

                if (ld.version.matches(".*[a-zA-Z-]+.*") && skipBeta) {  // skip alpha/beta/rc ..
                    logger.info("Skip lib: " + ld.name + "   version: " + ld.version);
                    continue;
                }

                logger.info("Parse lib: " + ld.name + "   version: " + ld.version);

                // if stats file not existing add new one
                if (!libName2Stats.containsKey(ld.name))
                    libName2Stats.put(ld.name, new LibApiStats(ld.name));

                libName2Stats.get(ld.name).versions.add(ld.version);

                // extract public API
                Set<IMethod> docAPIs = extractPublicApi(ld, meta2Code.get(libXML));
                libName2Stats.get(ld.name).setDocumentedAPIs(ld.version, docAPIs);

            } catch (Exception e) {
                logger.warn(Utils.stacktrace2Str(e));
            }
        }
    }


    private Set<IMethod> extractPublicApi(LibraryDescription ld, File libCodeFile) throws ClassHierarchyException, IOException, ClassNotFoundException {
        logger.debug("Process library: " + ld.name + " " + ld.version);

        // create analysis scope and generate class hierarchy
        final AnalysisScope scope = AnalysisScope.createJavaAnalysisScope();

        JarFile jf = libCodeFile.getName().endsWith(".aar")? new AarFile(libCodeFile).getJarFile() : new JarFile((libCodeFile));
        scope.addToScope(ClassLoaderReference.Application, jf);
        scope.addToScope(ClassLoaderReference.Primordial, new JarFile(TplCLI.CliOptions.pathToAndroidJar));
        IClassHierarchy cha = ClassHierarchy.make(scope);

        // cleanup tmp files if library input was an .aar file
        if (libCodeFile.getName().endsWith(".aar")) {
            File tmpJar = new File(jf.getName());
            tmpJar.delete();
            logger.trace(Utils.indent() + "tmp jar-file deleted at " + tmpJar.getName());
        }

        // return extracted documented API
        return PublicInterfaceExtractor.getDocumentedPublicInterface(cha);
    }


    /**
     * Find library descriptor files and their associated code package on disk (recursively)
     * @param basePath
     */
    private void locateLibrarySDKs(File basePath) {
        long s = System.currentTimeMillis();

        // recursively search for library.xml file and their associated code packages (.jar|.aar) within the same directory
        try {
            for (File f : Utils.collectFiles(basePath, new String[]{"xml"})) {
                if (f.getName().equals("library.xml")) {
                    logger.trace("Found lib.xml: " + f.getName() + "   parent: " + f.getParent() );

                    // grep the associated code package (TODO: prefer aar|jar?)
                    for (File j : Utils.collectFiles(f.getParentFile(), new String[]{"jar", "aar"})) {
                        logger.trace("    -> Found code pckg: " + j);
                        meta2Code.put(f,j);
                        break;
                    }

                } else
                    logger.trace("Found something different: " + f);
            }
        } catch (Exception e) {
            logger.warn(Utils.stacktrace2Str(e));
        }
    }



}
