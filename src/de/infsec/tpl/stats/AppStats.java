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

package de.infsec.tpl.stats;

import java.io.File;
import java.util.*;

import de.infsec.tpl.manifest.ProcessManifest;
import de.infsec.tpl.hash.HashTree;
import de.infsec.tpl.pkg.PackageTree;
import de.infsec.tpl.profile.LibProfile;
import de.infsec.tpl.profile.ProfileMatch;


public class AppStats implements Exportable {
	public File appFile;
	public ProcessManifest manifest;
	public boolean isMultiDex;
	
	public PackageTree pTree;
	public List<HashTree> appHashTrees;
		
	public List<LibProfile> profiles;
	public List<ProfileMatch> pMatches;
	public Map<String,String> packageOnlyMatches = new TreeMap<String,String>();  // lib name -> root package
	
	public long processingTime;
	
	
	public AppStats(File appFile) {
		this.appFile  = appFile;
	}

	@Override
	public Export export() {
		return new Export(this);
	}


	private class Export {
		 class AppInfo {
			String fileName;
			String appName;
			String packagename;
			Set<String> permissions;
			int versionCode;
			int versionMinSDK;
			int versionTargetSDK;
			String sharedUserId;
		}

		AppInfo appInfo = new AppInfo();

		int stats_packageCount;
		int stats_classCount;
		long stats_processingTime;

		// libraries detected via profiles
		List<ProfileMatch.Export> lib_matches;

		// includes only lib names (and their packages) that are not matched via profiles
		Map<String, String> lib_packageOnlyMatches = new TreeMap<String,String>();

		public Export(AppStats stats) {
			this.appInfo.fileName = stats.appFile.getName();
			this.appInfo.appName = stats.manifest.getApplicationName();
			this.appInfo.packagename = stats.manifest.getPackageName();
			this.appInfo.permissions = stats.manifest.getPermissions();
			this.appInfo.versionCode = stats.manifest.getVersionCode();
			this.appInfo.versionMinSDK = stats.manifest.getMinSdkVersion();
			this.appInfo.versionTargetSDK = stats.manifest.getTargetSdkVersion();
			this.appInfo.sharedUserId = stats.manifest.getSharedUserId();

			this.stats_packageCount = stats.pTree.getNumberOfNonEmptyPackages();
			this.stats_classCount = stats.pTree.getNumberOfAppClasses();
			this.stats_processingTime = stats.processingTime;

			this.lib_matches = new ArrayList<ProfileMatch.Export>();

			/*
			 * - only save profiles that at least match partially
			 * - if multiple profiles of the same library match (at least partially), only export the one(s) with the highest score
		 	*/
			Set<String> libsMatched = new HashSet<String>();

			// LibName -> List of ProfileMatches with highest sim scores
			HashMap<String, List<ProfileMatch>> exportedPMatches = new HashMap<String, List<ProfileMatch>>();

			for (ProfileMatch pm: stats.pMatches) {
				if (pm.getHighestSimScore() != null && pm.getHighestSimScore().simScore > ProfileMatch.MATCH_HTREE_NONE) {
					String libName = pm.lib.description.name;

					if (!exportedPMatches.containsKey(libName)) {
						// initialize list and add pm
						exportedPMatches.put(libName, new ArrayList<ProfileMatch>());
						exportedPMatches.get(libName).add(pm);
					} else {
						// check if we have to add this pm to existing list
						ProfileMatch firstPM = exportedPMatches.get(libName).get(0);

						if (firstPM.getHighestSimScore() != null && firstPM.getHighestSimScore().simScore.floatValue() < pm.getHighestSimScore().simScore.floatValue()) {
							// replace list
							exportedPMatches.get(libName).clear();
							exportedPMatches.get(libName).add(pm);
						} else if (firstPM.getHighestSimScore() != null && firstPM.getHighestSimScore().simScore.floatValue() == pm.getHighestSimScore().simScore.floatValue()) {
							// add to existing list
							exportedPMatches.get(libName).add(pm);
						}
					}

					libsMatched.add(libName);
				}
			}

			// save the PM's that are to be exported
			for (String libName: exportedPMatches.keySet()) {
				for (ProfileMatch pm: exportedPMatches.get(libName)) {
					this.lib_matches.add(pm.export());
					libsMatched.add(pm.lib.description.name);
				}
			}

			// save all library names that did not match via profiles but via root package name
			for (String matchedLibPckg: stats.packageOnlyMatches.keySet())
				if (!libsMatched.contains(matchedLibPckg)) {
					this.lib_packageOnlyMatches.put(matchedLibPckg, stats.packageOnlyMatches.get(matchedLibPckg));
				}
		}
	}
}
