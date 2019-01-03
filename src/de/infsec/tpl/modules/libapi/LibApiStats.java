package de.infsec.tpl.modules.libapi;

import com.github.zafarkhaja.semver.Version;
import com.ibm.wala.classLoader.IMethod;
import de.infsec.tpl.config.LibScoutConfig;
import de.infsec.tpl.stats.Exportable;
import de.infsec.tpl.utils.VersionWrapper;

import java.util.*;
import java.util.stream.Collectors;

/**
 * Container class to store library API changes across versions
  */
public class LibApiStats implements Exportable {
    public String libName;

    // set of version strings
    private Set<Version> versions;

    // maps documented API signatures to list of library versions including them
    public Map<IMethod, Set<Version>> api2Versions;

    public Map<Version, LibApiComparator.ApiDiff> version2Diff;

    public Map<Version, DependencyAnalysis.LibDependencies> version2Deps;


    public class Export {
        public String libName;

        public List<String> versions;

        public List<LibApiComparator.ApiDiff.Export> apiDiffs;

        public List<DependencyAnalysis.LibDependencies.Export> libDeps;

        // maps documented API signatures to list of library versions including them
        public Map<String, List<String>> api2Versions;


        public Export(LibApiStats stats) {
            this.libName = stats.libName;
            this.versions = stats.versions.stream().map(Version::toString).collect(Collectors.toList());

            this.apiDiffs = stats.version2Diff.values().stream().map(LibApiComparator.ApiDiff::export).collect(Collectors.toList());

            if (LibScoutConfig.libDependencyAnalysis)
                this.libDeps = stats.version2Deps.values().stream().map(DependencyAnalysis.LibDependencies::export).collect(Collectors.toList());

            this.api2Versions = new HashMap<>();
            for (IMethod m: stats.api2Versions.keySet()) {
                this.api2Versions.put(m.getSignature(), stats.api2Versions.get(m).stream().map(Version::toString).collect(Collectors.toList()));
            }
        }
    }

    @Override
    public Export export() {
        return new Export(this);
    }



    public LibApiStats(String libName) {
        this.libName = libName;
        this.api2Versions = new HashMap<>();
        this.versions = new TreeSet<>();
    }


	/*
	 * Update functions
	 */

	public void addVersion(String version) {
        versions.add(VersionWrapper.valueOf(version));
    }

    public Set<Version> getVersions() {
	    return versions;
    }

    void setDocumentedAPIs(String version, Set<IMethod> docAPIs) {
        for (IMethod api: docAPIs) {
            if (!api2Versions.containsKey(api))
                api2Versions.put(api, new TreeSet<Version>());

            api2Versions.get(api).add(VersionWrapper.valueOf(version));
        }
    }

    Set<IMethod> getDocumentedAPIs(Version version) {
        return api2Versions.keySet().stream().filter(m -> api2Versions.get(m).contains(version)).collect(Collectors.toSet());
    }


}
