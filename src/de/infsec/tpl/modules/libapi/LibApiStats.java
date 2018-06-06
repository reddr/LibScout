package de.infsec.tpl.modules.libapi;

import com.github.zafarkhaja.semver.Version;
import com.ibm.wala.classLoader.IMethod;

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


    private class Export {
        public String libName;

        public List<LibApiComparator.ApiDiff.Export> apiDiffs = new ArrayList<>();

        // maps documented API signatures to list of library versions including them
        public Map<String, Set<String>> api2Versions;


        public Export(LibApiStats stats) {
            this.libName = stats.libName;

            this.apiDiffs = stats.version2Diff.values().stream().map(LibApiComparator.ApiDiff::export).collect(Collectors.toList());

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

    public void setDocumentedAPIs(String version, Set<IMethod> docAPIs) {
        for (IMethod api: docAPIs) {
            if (!api2Versions.containsKey(api))
                api2Versions.put(api, new TreeSet<String>());

            api2Versions.get(api).add(version);
        }
    }






// STATISTICS :: SHARED METHODS across lib versions

// TODO
/*    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("\nLibrary: " + libName + "\n");
        for (String v: versions2docApiCount.keySet()) {
            sb.append("  - version: " + v + "  doc APIs: " + versions2docApiCount.get(v) + "\n");
        }
        return sb.toString();
    }
*/


    ///////////////////////////    OLD OLD   ///////////////////


/*

    public void updateCandidateApi(String originalApi, String alternativeApi) {
        if (!api2CandidateApis.containsKey(originalApi))
            api2CandidateApis.put(originalApi, new TreeSet<String>());

        api2CandidateApis.get(originalApi).add(alternativeApi);
    }

*/

	/*
	 * Information retrieval
	 */

//    public int getNumberOfPublicApis(String version) {
  //      return this.versions2pubApiCount.getOrDefault(version, -1);
   // }


  /*  public int getNumberOfNewerVersions(String version) {
        List<String> versions = new ArrayList<String>(versions2pubApiCount.keySet());
        int idx = versions.indexOf(version);

        return idx == -1? idx : versions.size() - idx -1;
    }
*/

    /**
     * Determine the number of subsequent versions which contain a specific API function.
     * @param signature   signature of the API method
     * @param version
     * @return
     */
 /*   public int getNumberOfStableVersions(String signature, String version) {
        List<String> allVersions = getSuccessorVersionsOf(version);

        if (api2Versions.containsKey(signature)) {
            List<String> versions = api2Versions.get(signature);
            versions = versions.subList(versions.indexOf(version)+1, versions.size());

            // check against all versions to detect version gaps, i.e.
            // if an api is removed in version x+1 but re-introduced in x+2
            int number = 0;
            for (String v: allVersions) {
                if (versions.contains(v))
                    number++;
                else
                    break;
            }

            return number;
        } else
            // signature is not existing in any version
            return -1;
    }
*/

    /**
     * Same as {@see #getNumberOfStableVersions(String, String)}, but instead of the number of stable versions
     * this method returns the version string of the latest version including the provided API
     * @param signature
     * @param version
     * @param returnSuccessor  if true, returns the first version that does not include the API
     * @return
     */
    /*public String getLatestVersionWithApi(String signature, String version, boolean returnSuccessor) {
        List<String> allVersions = getSuccessorVersionsOf(version);

        if (api2Versions.containsKey(signature)) {
            List<String> versions = api2Versions.get(signature);
            versions = versions.subList(versions.indexOf(version)+1, versions.size());

            // check against all versions to detect version gaps, i.e.
            // if an api is removed in version x+1 but re-introduced in x+2
            for (int i = 0; i < allVersions.size(); i++) {
                String v = allVersions.get(i);

                if (!versions.contains(v)) {
                    if (i == 0)  // API already missing in first successor version
                        return null;
                    else
                        return allVersions.get(returnSuccessor? i : i-1);
                }
            }

            return allVersions.get(allVersions.size()-1);
        } else
            // signature is not existing in any version
            return null;
    }*/
/*
    public String getLatestVersionWithApi(String signature, String version) {
        return getLatestVersionWithApi(signature, version, false);
    }




    public boolean isApiStable(String signature, String version) {
        return getNumberOfNewerVersions(version) == getNumberOfStableVersions(signature, version);
    }


    public boolean isApiIncludedIn(String signature, String version) {
        return api2Versions.containsKey(signature) && api2Versions.get(signature).contains(version);
    }


    public Set<String> getPublicApi(String version) {
        Set<String> pubApi = new TreeSet<String>();
        for (String api: api2Versions.keySet()) {
            if (api2Versions.get(api).contains(version))
                pubApi.add(api);
        }

        return pubApi;
    }


    private List<String> getSuccessorVersionsOf(String version) {
        if (!versions2pubApiCount.keySet().contains(version))
            return Collections.emptyList();
        else {
            List<String> allVersions = new ArrayList<String>(versions2pubApiCount.keySet());
            return allVersions.subList(allVersions.indexOf(version)+1, allVersions.size());
        }
    }
*/

    /**
     * Determine the number of fully-API compatible subsequent versions
     * @param version  start version
     * @return number of fully API-compatible successor versions
     */
  /*  public int getNumberOfApiCompatibleVersions(String version) {
        Set<String> pubApi = getPublicApi(version);

        int number = 0;
        for (String sucVersion: getSuccessorVersionsOf(version)) {
            Set<String> sucPubApi = getPublicApi(sucVersion);

            if (!sucPubApi.containsAll(pubApi))
                break;

            number++;
        }

        return number;
    }
*/

    /**
     * Get number of APIs that are stable across all successor versions
     * @param version
     * @return  number of stable APIs
     */
  /*  public int getNumberOfStablePublicApis(String version) {
        int stable = 0;

        for (String pubApi: getPublicApi(version)) {
            if (this.isApiStable(pubApi, version))
                stable++;
        }
        return stable;
    }
*/


}
