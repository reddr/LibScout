/*
 * Copyright (c) 2015-2017  Erik Derr [derr@cs.uni-saarland.de]
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this
 * file except in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under
 * the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */


package de.infsec.tpl.eval;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;


/**
 * Container class to store library API changes across versions
 * Includes information such as
 *   - # public APIs per version
 *   - APIs -> set of versions in which they are included
 *   - set of alternative APIs (if any), if API is no longer in some version
 */

public class LibApiRobustnessStats implements Serializable {
	private static final long serialVersionUID = -3951094682839938234L;

	public String libName;
	
	public Map<String, Integer> versions2pubApiCount;   // sorted by version
	
	// maps public API signatures to list of library versions including them
	public Map<String, List<String>> api2Versions;
	
	// if API is not stable for the entire version set, include a list of candidate APIs of the first non-matching version
	public Map<String, Set<String>> api2CandidateApis;
	
	
	public LibApiRobustnessStats(String libName) {
		this.libName = libName;
		this.versions2pubApiCount = new LinkedHashMap<String, Integer>();
		this.api2Versions = new HashMap<String, List<String>>();
		this.api2CandidateApis = new HashMap<String, Set<String>>();
	}
	

	
	/*
	 * Update functions
	 */
	
	public void updateApi(String signature, String version) {
		if (!api2Versions.containsKey(signature))
			api2Versions.put(signature, new ArrayList<String>());
		
		api2Versions.get(signature).add(version);
	}
	

	public void updateCandidateApi(String originalApi, String alternativeApi) {
		if (!api2CandidateApis.containsKey(originalApi))
			api2CandidateApis.put(originalApi, new TreeSet<String>());
		
		api2CandidateApis.get(originalApi).add(alternativeApi);
	}
	
	

	/*
	 * Information retrieval
	 */
	
	public int getNumberOfPublicApis(String version) {
		return this.versions2pubApiCount.getOrDefault(version, -1);
	}

	
	
	public int getNumberOfNewerVersions(String version) {
		List<String> versions = new ArrayList<String>(versions2pubApiCount.keySet());
		int idx = versions.indexOf(version);
	     
		return idx == -1? idx : versions.size() - idx -1;
	}
	
	
	/**
	 * Determine the number of subsequent versions which contain a specific API function.
	 * @param signature   signature of the API method
	 * @param version
	 * @return
	 */
	public int getNumberOfStableVersions(String signature, String version) {
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
	

	/**
	 * Same as {@see #getNumberOfStableVersions(String, String)}, but instead of the number of stable versions
	 * this method returns the version string of the latest version including the provided API
	 * @param signature
	 * @param version
	 * @param returnSuccessor  if true, returns the first version that does not include the API
	 * @return
	 */
	public String getLatestVersionWithApi(String signature, String version, boolean returnSuccessor) {
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
	}

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
	
	
	/**
	 * Determine the number of fully-API compatible subsequent versions
	 * @param version  start version
	 * @return number of fully API-compatible successor versions
	 */
	public int getNumberOfApiCompatibleVersions(String version) {
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


	/**
	 * Get number of APIs that are stable across all successor versions
	 * @param version
	 * @return  number of stable APIs
	 */
	public int getNumberOfStablePublicApis(String version) {
		int stable = 0;
		
		for (String pubApi: getPublicApi(version)) {
			if (this.isApiStable(pubApi, version))
				stable++;
		}
		return stable;
	}
}
