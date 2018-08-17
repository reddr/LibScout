package de.infsec.tpl.modules.libapi;

import com.ibm.wala.classLoader.CallSiteReference;
import com.ibm.wala.classLoader.IClass;
import com.ibm.wala.classLoader.IMethod;
import com.ibm.wala.shrikeCT.InvalidClassFileException;
import de.infsec.tpl.pkg.PackageTree;
import de.infsec.tpl.pkg.PackageUtils;
import de.infsec.tpl.stats.Exportable;
import de.infsec.tpl.utils.Utils;
import de.infsec.tpl.utils.WalaUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;
import java.util.stream.Collectors;


/**
 * Feature: Tests for nested/secondary library dependencies, i.e. libraries depending on other libraries.
 * The analysis is performed for every documented API of every lib version via reachability analysis
 */
public class DependencyAnalysis {
    private static final Logger logger = LoggerFactory.getLogger(DependencyAnalysis.class);

    /**
     * Secondary lib dependencies for every version and documented API
     */
    class LibDependencies implements Exportable {
        String version;

        // documented APIs to set of APIs from dependencies
        Map<IMethod, Set<CallSiteReference>> api2Dependencies;

        LibDependencies(String version, Map<IMethod, Set<CallSiteReference>> api2Dependencies) {
            this.version = version;
            this.api2Dependencies = api2Dependencies;
        }

        @Override
        public DependencyAnalysis.LibDependencies.Export export() {
            return new Export(this);
        }


        public class Export {
            String version;
            Map<String, Set<String>> api2Dependencies = new HashMap<String, Set<String>>();

            public Export(LibDependencies deps) {
                this.version = deps.version;

                for (IMethod m: deps.api2Dependencies.keySet())
                    this.api2Dependencies.put(m.getSignature(), deps.api2Dependencies.get(m).stream().map(c -> c.getDeclaredTarget().getSignature()).sorted().collect(Collectors.toSet()));
            }
        }
    }




    // need to infer expected and actual semver
    protected Map<String, DependencyAnalysis.LibDependencies> run(LibApiStats stats) {
        Map<String, LibDependencies> version2Deps = new TreeMap<String, LibDependencies>();

        for (String version: stats.versions) {
            logger.info(Utils.INDENT + "- version: " + version);
            Map<IMethod, Set<CallSiteReference>> api2Dependencies = analyzeDependencies(stats.getDocumentedAPIs(version));
            version2Deps.put(version, new LibDependencies(version, api2Dependencies));
        }


        // debug collect all dependencies (APIs) per lib (incl. all versions)
        Set<String> signatures = new TreeSet<String>();
        version2Deps.values().
                forEach(ld -> {
                    ld.api2Dependencies.values()
                        .forEach(set -> {
                            set.forEach(csf -> signatures.add(PackageUtils.getPackageName(csf.getDeclaredTarget().getSignature())));
                        })
                    ;}
                );

        logger.info(Utils.INDENT + "-> Dependencies of " + stats.libName);
        signatures.forEach(s -> logger.info(Utils.INDENT2 + "- dep: " + s));
        PackageTree pt = PackageTree.make(signatures);
        pt.print(true);
        /// TODO show empty packages + non-empty on depth == 1

        return version2Deps;
    }


    private Map<IMethod, Set<CallSiteReference>> analyzeDependencies(Set<IMethod> pubApis) {
        HashMap<IMethod, Set<CallSiteReference>> secDeps = new HashMap<IMethod, Set<CallSiteReference>>();

        // perform method reachability analysis for every pubAPI
        for (IMethod docApi: pubApis) {
            logger.debug("-> check API: " + docApi.getSignature());

            LinkedList<IMethod> queue = new LinkedList<IMethod>();
            queue.push(docApi);

            // types to methods signatures in which they are used
            Set<CallSiteReference> unresolvedCalls = new HashSet<CallSiteReference>();
            Set<String> visited = new HashSet<String>();

            // Check method invocations
            try {
                while (!queue.isEmpty()) {
                    IMethod m = queue.poll();

                    if (!visited.add(m.getSignature()))
                        continue;

                    for (CallSiteReference csf : com.ibm.wala.classLoader.CodeScanner.getCallSites(m)) {
                        IClass c = m.getClassHierarchy().lookupClass(csf.getDeclaredTarget().getDeclaringClass());
                        IMethod inv = m.getClassHierarchy().resolveMethod(csf.getDeclaredTarget());

                        if (inv == null) {
                            // inherited final methods can not be looked up or (abstract) interface methods inherited from another interface
                            // workaround, we check if the class is part of the CHA
                            if (c == null) {
                                logger.trace("         ## unresolved call: " + csf.getDeclaredTarget().getSignature() + (csf.isInterface() ? "  [Interface]" : ""));
                                unresolvedCalls.add(csf);
                            }
                        } else {
                            if (c != null && WalaUtils.isAppClass(c))
                                queue.push(inv);
                        }
                    }
                }
            } catch (InvalidClassFileException e) {
                logger.error(Utils.stacktrace2Str(e));
            }

            if (!unresolvedCalls.isEmpty()) {
                secDeps.put(docApi, unresolvedCalls);
            }
        }


        // Results
        secDeps.keySet()
                .forEach(m -> {
                    logger.debug("- Method: " + m.getSignature());
                    secDeps.get(m).stream()
                            .map(c -> c.getDeclaredTarget().getSignature())
                            .sorted().distinct()
                            .forEach(s -> logger.debug("  - dep: " + s));
                });

        logger.info(Utils.INDENT2 + "- " + secDeps.size() + "/" + pubApis.size() + " APIs with secondary dependencies");

        return secDeps;
    }




/*    private void printSTATS(){
        logger.info("# Processed libs: " + libName2Stats.size());

        logger.info("  - w/o secondary dependencies: " + libName2Stats.values().stream().filter(s -> s.version2Dependencies.isEmpty()).count());
        libName2Stats.values().stream().filter(s -> s.version2Dependencies.isEmpty()).forEach(st -> logger.error(Utils.INDENT + "- lib: " + st.libName));

        Set<String> rootPackages = new TreeSet<String>();
        libName2Stats.values().stream().map(s -> s.rootPackages).forEach(rootPackages::addAll);
//        rootPackages.forEach(rp -> logger.error("-- root pckg: " + rp));

        logger.info("  - with secondary dependencies: " + libName2Stats.values().stream().filter(s -> s.version2Dependencies.size() > 0).count());
        libName2Stats.values().forEach(s -> {
            s.version2Dependencies.keySet().forEach(v -> {
                Set<String> prunedDeps = new TreeSet<String>();
                for (String dep: s.version2Dependencies.get(v)) {
                    boolean added = false;
                    for (String rp: rootPackages) {
                        if (dep.startsWith(rp)) {
                            added = true;
                            prunedDeps.add(rp);
                            break;
                        }
                    }
                    if (!added) prunedDeps.add(dep);
                };
                s.version2Dependencies.put(v, prunedDeps);
            });

        });

        for (LibApiStats stats: libName2Stats.values()) {
            if (!stats.version2Dependencies.isEmpty()) {
                logger.info(Utils.INDENT + "- lib: " + stats.libName);

                // per lib package dep
                Set<String> perLibDep = new TreeSet<String>();
                stats.version2Dependencies.values().forEach(perLibDep::addAll);
                perLibDep.forEach(dep -> logger.info(Utils.INDENT2 + "- dep: " + dep));
*/
                // per version package dep
                /*for (String v: stats.version2Dependencies.keySet().stream().sorted().collect(Collectors.toList())) {
                    logger.info("     - version: " + v);
                    for (String dep: stats.version2Dependencies.get(v))
                        logger.info("          -- dep: " + dep);
                }*/

  /*          }
        }
    }*/


}
