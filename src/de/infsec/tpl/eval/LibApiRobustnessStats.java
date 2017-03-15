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
import java.util.Comparator;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.infsec.tpl.utils.MathUtils;
import de.infsec.tpl.utils.Utils;


public class LibApiRobustnessStats implements Serializable {
	private static final long serialVersionUID = 1522282237387132588L;

	// TODO TODO
	// -store how often unstable api is due to major version or minor or sub-minor!
	// - check api compatibility additionally for all versions within major versions, e.g. for facebook 3.x and 4.x
	
	
// TODO: release date for sorting! -- superseeded by semver
// TODO: store number of pub api	
	public String lib;
	public String version;
	public int newerVersions;  // number of newer versions available
	
	// API -> # of subsequent versions in which it is stable
	public Map<String,Integer> api2StableVersions = new HashMap<String, Integer>();

	// if API is not stable for the entire version set, include a list of candidate APIs of the first non-matching version
	public Map<String, Set<String>> api2CandidateApis = new HashMap<String, Set<String>>();
	
	public LibApiRobustnessStats(String libName, String libversion) {
		this.lib = libName;
		this.version = libversion;
	}
	
	public int minApiCompatibleWithNextVersion() {
		Optional<Integer> min = api2StableVersions.values().stream().min(Comparator.naturalOrder());
		return min.isPresent()? min.get() : -1;
	}
	
	public boolean apiCompatibleWithNextVersion() {
		return !api2StableVersions.values().contains(0);
	}

	
	public int getNumberOfPublicApis() {
		return this.api2StableVersions.size();
	}

	public int getNumberOfStablePublicApis() {
		int stable = 0;
		for (String pubApi: this.api2StableVersions.keySet()) {
			if (this.isApiStable(pubApi))
				stable++;
		}
		return stable;
	}
	
	public boolean isApiStable(String sig) {
		return newerVersions == api2StableVersions.get(sig);
	}
	
	public int isApiStableOrExisting(String sig) {
		if (!api2StableVersions.containsKey(sig))
			return -1;
		else if (newerVersions == api2StableVersions.get(sig))
			return 1;
		else 
			return 0;
	}
}
