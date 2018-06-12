package de.infsec.tpl.modules.libapi;

import com.github.zafarkhaja.semver.Version;
import com.ibm.wala.classLoader.IMethod;
import de.infsec.tpl.TplCLI;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;
import java.util.stream.Collectors;

/**
 * Container class to store library API changes across versions
  */
public class LibApiStats {
    public String libName;

    // set of version strings
    public Set<String> versions;

    // maps documented API signatures to list of library versions including them
    public Map<IMethod, Set<String>> api2Versions;

    public Map<Version, LibApiComparator.ApiDiff> version2Diff;

    public Map<String, DependencyAnalysis.LibDependencies> version2Deps;


    private class Export {
        public String libName;

        public List<LibApiComparator.ApiDiff.Export> apiDiffs;

        public List<DependencyAnalysis.LibDependencies.Export> libDeps;

        // maps documented API signatures to list of library versions including them
        public Map<String, Set<String>> api2Versions;


        public Export(LibApiStats stats) {
            this.libName = stats.libName;

            this.apiDiffs = stats.version2Diff.values().stream().map(LibApiComparator.ApiDiff::export).collect(Collectors.toList());

            if (TplCLI.CliOptions.libDependencyAnalysis)
                this.libDeps = stats.version2Deps.values().stream().map(DependencyAnalysis.LibDependencies::export).collect(Collectors.toList());

            this.api2Versions = new HashMap<String, Set<String>>();
            for (IMethod m: stats.api2Versions.keySet()) {
                this.api2Versions.put(m.getSignature(), stats.api2Versions.get(m));
            }
        }
    }

    public Export export() {
        return new Export(this);
    }



    public LibApiStats(String libName) {
        this.libName = libName;
        this.api2Versions = new HashMap<IMethod, Set<String>>();
        this.versions = new TreeSet<String>();
    }


	/*
	 * Update functions
	 */

    void setDocumentedAPIs(String version, Set<IMethod> docAPIs) {
        for (IMethod api: docAPIs) {
            if (!api2Versions.containsKey(api))
                api2Versions.put(api, new TreeSet<String>());

            api2Versions.get(api).add(version);
        }
    }

    Set<IMethod> getDocumentedAPIs(String version) {
        return api2Versions.keySet().stream().filter(m -> api2Versions.get(m).contains(version)).collect(Collectors.toSet());
    }


}
