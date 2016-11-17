/*
 * Copyright (c) 2015-2016  Erik Derr [derr@cs.uni-saarland.de]
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

package de.infsec.tpl.stats;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import de.infsec.tpl.manifest.ProcessManifest;
import de.infsec.tpl.profile.ProfileMatch;
import de.infsec.tpl.profile.SerializableProfileMatch;


public class SerializableAppStats implements Serializable {
	private static final long serialVersionUID = -5051966487916476377L;
	
	public String appFileName;
	public ProcessManifest manifest;
	
	public int appPackageCount;
	public int appClassCount;
	
	public List<SerializableProfileMatch> pMatches;
	public Set<String> packageMatches; // includes only library names that are not matched via profiles

	public long processingTime;
	
	
	public SerializableAppStats(AppStats stats) {
		this.appFileName  = stats.appFile.getName();
		this.manifest = stats.manifest;
		this.appPackageCount = stats.pTree.getNumberOfNonEmptyPackages();
		this.appClassCount = stats.pTree.getNumberOfAppClasses();

		Set<String> libsMatched = new HashSet<String>();
		
		pMatches = new ArrayList<SerializableProfileMatch>();
		for (ProfileMatch pm: stats.pMatches) {
			// only save profiles that at least match partially
			if (pm.getHighestSimScore() != null && pm.getHighestSimScore().simScore > ProfileMatch.MATCH_HTREE_NONE) {
				pMatches.add(new SerializableProfileMatch(pm));
				libsMatched.add(pm.lib.description.name);
			}
		}
	
		// save all library names that did not match via profiles but via root package name
		this.packageMatches = new HashSet<String>();
		for (String matchedLibPckg: stats.packageMatches)
			if (!libsMatched.contains(matchedLibPckg))
				this.packageMatches.add(matchedLibPckg);
		
		this.processingTime = stats.processingTime;
	}
}
