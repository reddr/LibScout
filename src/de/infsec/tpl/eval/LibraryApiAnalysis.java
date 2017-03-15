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

import java.io.File;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.github.zafarkhaja.semver.Version;

import de.infsec.tpl.hash.AccessFlags;
import de.infsec.tpl.hash.Hash;
import de.infsec.tpl.hash.HashTree;
import de.infsec.tpl.profile.LibProfile;
import de.infsec.tpl.profile.LibProfile.LibProfileComparator;
import de.infsec.tpl.utils.MapUtils;
import de.infsec.tpl.utils.MathUtils;
import de.infsec.tpl.utils.Utils;
import de.infsec.tpl.utils.VersionWrapper;
import de.infsec.tpl.utils.WalaUtils;


/**
 * Check how different library versions differ in their public API
 * @author ederr
 *
 */
public class LibraryApiAnalysis {
	private static final Logger logger = LoggerFactory.getLogger(de.infsec.tpl.eval.LibraryApiAnalysis.class);
	private static List<LibProfile> profiles; 
	private static Map<String, List<String>> report;
	
	// Library name to percentage of correct semver values, e.g. Admob -> 35.1%
	private static Map<String, Float> libSemverValues = new HashMap<String, Float>();
	
	private static int numberOfAnalyzedLibs;


	// expected|real count per lib how often patch|minor|major version occur
	HashMap<String,Integer> semverExpChangeCountGlobal = new HashMap<String,Integer>() {{
		put("patch", 0); put("minor", 0); put("major", 0);
	}};
	HashMap<String,Integer> semverRealChangeCountGlobal = new HashMap<String,Integer>() {{
		put("patch", 0); put("minor", 0); put("major", 0);
	}};

	private HashMap<String, Integer> semVerInconsistenciesGlobal = new HashMap<String, Integer>();
	
	private Map<String, List<String>> sortedVersionsCache = new HashMap<String, List<String>>();
	private ArrayList<LibApiRobustnessStats> libStats = new ArrayList<LibApiRobustnessStats>();
	
	
	/**
	 * Runs the library api robustness analysis
	 * NOTE: This requires profiles built with TRACE verboseness and public only filter
	 * @param libProfiles
	 */
	public void run(List<LibProfile> libProfiles) {
		profiles = libProfiles;
		TreeSet<String> uniqueLibraries = new TreeSet<String>(LibProfile.getUniqueLibraries(profiles).keySet());

		logger.info("= Evaluate libraries =");
		logger.info(Utils.INDENT + "Loaded " + profiles.size() + " library profiles for " + uniqueLibraries.size() + " distinct libraries");

		logger.info("- Evaluate public library API -");
		numberOfAnalyzedLibs = 0;

		final String[] semVerKeys = new String[]{"patch->major", "minor->major", "patch->minor", "minor->patch", "major->patch", "major->minor" };  // sorted by severity desc
		for (String k: semVerKeys)
			semVerInconsistenciesGlobal.put(k, 0);

		report = new HashMap<String, List<String>>();
		for (String lib: uniqueLibraries) {
			checkPublicAPI(lib, true);
		}
		
		// print results
		printResults(uniqueLibraries, semVerKeys);

		// serialize to disk
		Utils.object2Disk(new File("./libApiEval.lstats"), libStats);
	}

	
	
	/**
	 * Checks for each <library, version> the stableness of each declared public API, i.e.
	 * for each public API determine the highest library version for which this exact API is available 
	 * @param libName   
	 * @param startVersion
	 * @param skipBeta
	 * @return  a {@link LibApiRobustnessStats} 
	 */
	private LibApiRobustnessStats checkPerApiRobustness(String libName, String startVersion, boolean skipBeta) {
		LibApiRobustnessStats aStats = new LibApiRobustnessStats(libName, startVersion);   // TODO: one stats obj per lib
		
		List<LibProfile> list = getSortedLibProfiles(libName, startVersion, skipBeta, false, 10);
		logger.info("= Check lib: " + libName + "  # versions: " + list.size() + "  target version: " + startVersion + "  =");		
	
	    // how many newer API versions exist?
		aStats.newerVersions = list.size() -1;
		
		// for each public API in this version check the maximum library version for which this API is stable
		// if it is not stable beginning at some version, try to get alternatives (API methods that were introduced with the newer version)
		for (String sig: list.get(0).hashTrees.iterator().next().getAllMethodSignatures()) {
			aStats.api2StableVersions.put(sig, aStats.newerVersions);
			
			for (int k = 1; k < list.size(); k++) {
				LibProfile lp = list.get(k);
			
				boolean isIncluded = lp.hashTrees.iterator().next().getAllMethodSignatures().contains(sig);

				if (!isIncluded) {
					aStats.api2StableVersions.put(sig, k-1);
// TODO: collect stats about replacements, classify replacements
// TODO: do advanced check whether and how changed api could still be stable (classhierarchy check for arg|ret types (super types?)
// TODO: check candidates also by fixed selector but different name?
					// is there a new candidate API as replacement?
					List<String> apiList = lp.hashTrees.iterator().next().getAllMethodSignatures();
					String methodName = sig.substring(0, sig.indexOf("("));

					for (String new_api_sig: apiList) {
						if (new_api_sig.startsWith(methodName) &&
							!list.get(0).hashTrees.iterator().next().getAllMethodSignatures().contains(new_api_sig)) {  // print only if it's an API that was not in the former lib version

							if (!aStats.api2CandidateApis.containsKey(aStats))
								aStats.api2CandidateApis.put(sig, new TreeSet<String>());
							
							aStats.api2CandidateApis.get(sig).add(new_api_sig);
						}
					}
				
					break;
				}
			}
		}
		
		return aStats;
	}
		
	
	
	/**
	 * General unspecific API robustness check (checks whether *all* public API methods are included in next version)	
	 * @param lib
	 * @param skipBeta
	 */
	private void checkPublicAPI(String lib, boolean skipBeta) {
		List<LibProfile> list = getSortedLibProfiles(lib, skipBeta);
		
		if (list.isEmpty())
			return;
		else
			numberOfAnalyzedLibs++;
				
		String cat = list.get(0).description.category.toString();
		if (!report.containsKey(cat))
			report.put(cat, new ArrayList<String>());
		
		logger.info("Name,        Version,  Release-Date,   pubApi.size(),  API diff,  API compatible?,  Expected SemVer,  actual SemVer?,   semVer match?");
		float avgDiff = 0f;
		int apiCompatibleCount = 0;
		int semVerCorrect = 0;

		// expected|real count per lib how often patch|minor|major version occur
		HashMap<String,Integer> semverExpChangeCountLib = new HashMap<String,Integer>() {{
			put("patch", 0); put("minor", 0); put("major", 0);
		}};
		HashMap<String,Integer> semverRealChangeCountLib = new HashMap<String,Integer>() {{
			put("patch", 0); put("minor", 0); put("major", 0);
		}};
		
		// Record number of semver inconsistencies per type (expected -> actual semver)
		final String[] semVerKeys = new String[]{"patch->major", "minor->major", "patch->minor", "minor->patch", "major->patch", "major->minor" };  // sorted by severity desc

		// Key: Expected vs real semver, e.g. minor->patch    Value: # of instances
		HashMap<String, Integer> semVerInconsistencies = new HashMap<String, Integer>();
		for (String k: semVerKeys)
			semVerInconsistencies.put(k, 0);
		
		for (int i = 0; i < list.size(); i++) {
			LibProfile lp1 = list.get(i);
			HashTree pubTree1 = HashTree.getTreeByConfig(lp1.hashTrees, false, AccessFlags.getPublicOnlyFilter(), false);
			List<String> pubAPI1all = pubTree1.getAllMethodSignatures();

			// filter pub methods of anonymous inner classes
			List<String> pubAPI1 = new ArrayList<String>();
			for (String api: pubAPI1all) {
				if (!api.contains("$")) //!WalaUtils.isAnonymousInnerClass(api))
					pubAPI1.add(api);
			}
			
			if (i == 0) {
				logger.info(String.format("%s, %7s, %12s, %5d", lp1.description.name, lp1.description.version, lp1.description.getFormattedDate(), pubAPI1.size()));
			} else {
				LibProfile lp0 = list.get(i-1);
				HashTree pubTree0 = HashTree.getTreeByConfig(lp0.hashTrees, false, AccessFlags.getPublicOnlyFilter(), false);
				List<String> pubAPI0all = pubTree0.getAllMethodSignatures();

				List<String> pubAPI0 = new ArrayList<String>();
				for (String api: pubAPI0all) {
					if (!api.contains("$"))//if (!WalaUtils.isAnonymousInnerClass(api))
						pubAPI0.add(api);
				}
				
				boolean apiCompatible = pubAPI1.containsAll(pubAPI0);  // semver: major version change?
				boolean apiEquals = pubAPI0.size() == pubAPI1.size() && apiCompatible;  
				String semVer = apiEquals? "patch" : apiCompatible? "minor" : "major";
				
				apiCompatibleCount += apiCompatible? 1 : 0;
			
				String  expectedSemVer = VersionWrapper.determineVersionChange(lp0.description.version, lp1.description.version);
				if (expectedSemVer == null)  {
					logger.debug("[error in version comparison]  old: " + lp0.description.version + "  new: " + lp1.description.version);
					break;  // error that needs to be investigated
				}
				
				boolean semVerEqual = expectedSemVer == semVer;
				semVerCorrect += semVerEqual? 1 : 0;
				
				semverExpChangeCountLib.put(expectedSemVer, semverExpChangeCountLib.get(expectedSemVer)+1);
				semverRealChangeCountLib.put(semVer, semverRealChangeCountLib.get(semVer)+1);
				
				semverExpChangeCountGlobal.put(expectedSemVer, semverExpChangeCountGlobal.get(expectedSemVer)+1);
				semverRealChangeCountGlobal.put(semVer, semverRealChangeCountGlobal.get(semVer)+1);


				if (!semVerEqual) {
					String key = expectedSemVer + "->" + semVer;
					semVerInconsistencies.put(key, semVerInconsistencies.get(key)+1);
				}

				// what changed (in terms of API)?
				int apiAdded = 0;
				int apiRemoved = 0;
				
				for (String api: pubAPI1) {
					if (!pubAPI0.contains(api)) {
						apiAdded++;
					}
				}
				for (String api: pubAPI0) {
					if (!pubAPI1.contains(api)) {
						apiRemoved++;
					}
				}
// TODO check if similar version has been added if removed (i.e. changes in arg type list etc)				
				int apiDiff = apiAdded + apiRemoved;
				avgDiff += apiDiff;

				String apiDiffStr = (apiAdded == 0 ? "" : "+" + apiAdded) +  (apiRemoved == 0? "" : (" / -" + apiRemoved));
				logger.info(String.format("%s, %7s, %12s, %5d, %-10s, %-10b, %-20s, %-10s, %-10b", lp1.description.name, lp1.description.version, lp1.description.getFormattedDate(), pubAPI1.size(), apiDiffStr.isEmpty()? " -- " : apiDiffStr, apiCompatible, expectedSemVer, semVer, semVerEqual));//hashEqual));
				for (String api: pubAPI1) {
					if (!pubAPI0.contains(api)) {
						logger.debug(Utils.INDENT + "# new API: " + api);
					}
				}
				for (String api: pubAPI0) {
					if (!pubAPI1.contains(api)) {
						logger.debug(Utils.INDENT + "# removed API: " + api);
					}
				}


			}
		}
		logger.info("  ==>  average API diff: " + (avgDiff / (float) list.size()) + "  api compatible: " + apiCompatibleCount + "/" + list.size() + " (" + MathUtils.computePercentage(apiCompatibleCount, list.size())  + "%)");
		
		// change count
		logger.info("  ==> version change classification: ");
		logger.info("     [expected change count] patch: " + semverExpChangeCountLib.get("patch") + "   minor:  " + semverExpChangeCountLib.get("minor") + "   major: " + semverExpChangeCountLib.get("major"));
		logger.info("     [    real change count] patch: " + semverRealChangeCountLib.get("patch") + "   minor:  " + semverRealChangeCountLib.get("minor") + "   major: " + semverRealChangeCountLib.get("major"));
		
		logger.info("  ==>  SemVer correct: " + semVerCorrect + "/" + (list.size()-1) + " (" + MathUtils.computePercentage(semVerCorrect, list.size()-1) + "%)");
		for (String key: semVerKeys) {
			logger.info("       =>  SemVer inconsistencies (expected->real): " + key + "  : " + semVerInconsistencies.get(key) + "/" + (list.size() - 1 - semVerCorrect) + "  (" + MathUtils.computePercentage(semVerInconsistencies.get(key), (list.size() -1 - semVerCorrect)) + "%)");
			semVerInconsistenciesGlobal.put(key, semVerInconsistenciesGlobal.get(key) + semVerInconsistencies.get(key));
		}
	
		logger.info("");
		
		report.get(cat).add(Utils.INDENT + "# " + list.get(0).description.name + " (" + list.get(0).description.category + ")");
		report.get(cat).add(Utils.INDENT2 + "- average API diff: " + (avgDiff / (float) list.size()) + "  api compatible: " + apiCompatibleCount + "/" + list.size() + " (" + MathUtils.computePercentage(apiCompatibleCount, list.size())  + "%)");
		
		float semverCorrectPer = MathUtils.computePercentage(semVerCorrect, list.size());
		report.get(cat).add(Utils.INDENT2 + "- SemVer correct: " + semVerCorrect + "/" + list.size() + " (" + semverCorrectPer + "%)");

		
		libSemverValues.put(list.get(0).description.name, semverCorrectPer);
	}
	
	
	
	private void printResults(Set<String> uniqueLibraries, String[] semVerKeys) {
		logger.info("");
		logger.info("= Report =");
		for (String category: report.keySet()) {
			logger.info("## Category: " + category + " ##");
			for (String line: report.get(category))
				logger.info(line);
		}
		
		logger.info("");
		
		
		long semver80plusCount = libSemverValues.values().stream().filter(f -> f.floatValue() > 80f).count();
		logger.info("SemVer correct > 80%: " + semver80plusCount + " / " + numberOfAnalyzedLibs + "  (" + MathUtils.computePercentage(semver80plusCount, numberOfAnalyzedLibs) + "%)");
		
		long semver20MinusCount = libSemverValues.values().stream().filter(f -> f.floatValue() < 20f).count();
		logger.info("SemVer correct < 20%: " + semver20MinusCount + " / " + numberOfAnalyzedLibs + "  (" + MathUtils.computePercentage(semver20MinusCount, numberOfAnalyzedLibs) + "%)");
		
		libSemverValues.entrySet().stream()
			.filter(e -> e.getValue().floatValue() < 20f || e.getValue().floatValue() > 80f)
			.sorted(Map.Entry.<String, Float> comparingByValue().reversed())
		    .forEach(e -> logger.info(Utils.INDENT + "- " + e.getKey() + ": " + e.getValue()));
		
		logger.info("");
		logger.info("SemVer correct average: " + MathUtils.average(libSemverValues.values()) + "   median: " + MathUtils.median(libSemverValues.values()));

		
		int count = 0;
		for (String k: semVerInconsistenciesGlobal.keySet())
			count += semVerInconsistenciesGlobal.get(k);
		
		for (String key: semVerKeys) {
			logger.info("       =>  SemVer inconsistencies (expected->real): " + key + "  : " + semVerInconsistenciesGlobal.get(key) + "/" + (count) + "  (" + MathUtils.computePercentage(semVerInconsistenciesGlobal.get(key), count) + "%)");
		}
		
		
		// change count
		int totalVersions = semverExpChangeCountGlobal.get("patch") + semverExpChangeCountGlobal.get("minor") + semverExpChangeCountGlobal.get("major");
		logger.info(" = total libs: " + numberOfAnalyzedLibs + "  versions:  "+ totalVersions);
		logger.info("   [expected change count] patch: " + semverExpChangeCountGlobal.get("patch") + "   minor:  " + semverExpChangeCountGlobal.get("minor") + "   major: " + semverExpChangeCountGlobal.get("major"));
		logger.info("   [    real change count] patch: " + semverRealChangeCountGlobal.get("patch") + "   minor:  " + semverRealChangeCountGlobal.get("minor") + "   major: " + semverRealChangeCountGlobal.get("major"));

		

		logger.info("----------------------------------------------");
		logger.info("- per-lib-api robustness analysis -");
		final boolean skipBeta = true;
		
		for (String ulib: uniqueLibraries) {
			List<LibProfile> list = getSortedLibProfiles(ulib, skipBeta);
			
			for (LibProfile lp: list) {
				LibApiRobustnessStats stats = checkPerApiRobustness(lp.description.name, lp.description.version, skipBeta);
				if (stats != null) {
					libStats.add(stats);
					printApiStats(stats);
					logger.info("");
				}
			}
		}
	}
	
	
	
	/**
	 * Works like {@link #getSortedLibProfiles(String, boolean, boolean, int) with preset skipNoReleaseDate and minNumberOfLibs.
	 * @param libname
	 * @param skipBeta  true, if rc, alpha, beta versions are to be filtered
 	 * @return a sorted list of {@link LibProfiĺe}
	 */
	private List<LibProfile> getSortedLibProfiles(String libName, boolean skipBeta) {
		return getSortedLibProfiles(libName, skipBeta, false, 10);
	}


	/**
	 * Works like {@link #getSortedLibProfiles(String, String, boolean, boolean, int). No startVersion is provided here.
	 * @param libname
	 * @param skipBeta  true, if rc, alpha, beta versions are to be filtered
	 * @param skipNoReleaseDate   if true, version with no release date are skipped 
	 * @param minNumberOfLibs  return an empty list of there are less versions available
	 * @return a sorted list of {@link LibProfiĺe}
	 */
	
	private List<LibProfile> getSortedLibProfiles(String libName, boolean skipBeta, boolean skipNoReleaseDate, int minNumberOfLibs) {
		return getSortedLibProfiles(libName, null, skipBeta, skipNoReleaseDate, minNumberOfLibs);
	}

	

	/**
	 * Return a list of {@link LibProfile} sorted by name and version.
	 * @param libName   library name to match
	 * @param startVersion   version to start with or null to include any version
	 * @param skipBeta   if true, rc, alpha, beta versions are to be filtered
	 * @param skipNoReleaseDate   if true, version with no release date are skipped 
	 * @param minNumberOfLibs  return an empty list of there are less versions available
	 * @return  a sorted list of {@link LibProfile}
	 */
	private List<LibProfile> getSortedLibProfiles(String libName, String startVersion, boolean skipBeta, boolean skipNoReleaseDate, int minNumberOfLibs) {
		List<LibProfile> list = new ArrayList<LibProfile>();

		// filter versions (non-final versions, versions without release data)
		boolean found = startVersion == null;
		
		for (LibProfile lp: profiles) {
			if (lp.description.name.equals(libName)) {
				if (found || lp.description.version.equals(startVersion))
					found = true;
				else
					continue;
				
			
				// if there is at least one version without release-date skip this library
				if (lp.description.date == null && skipNoReleaseDate) {
					logger.info(Utils.INDENT + "[getSortedLibProfiles] skip lib " + libName + " due to missing release dates!");
					return new ArrayList<LibProfile>();
				} else {
					if (!lp.description.version.matches(".*[a-zA-Z]+.*") || !skipBeta)  // skip alpha/beta/rc ..
						list.add(lp);
				}
			}
		}
		
		/*
		 * return empty list iff
		 *   - we did not find a provided startVersion
		 *   - if the startVersion is the lastest version (i.e. list.size == 1)
		 *   - if the number of libs is below the threshold
		 */
		if (!found || list.size() == 1 || list.size() < minNumberOfLibs) {
			if (!found)
				logger.warn("Target library version " + startVersion + " is not in the list - ABORT!");
			else if (found && list.size() == 1)
				logger.info(Utils.indent() + "- Target library version " + startVersion + " is the last entry - nothing to check - ABORT!");
			else if (list.size() < minNumberOfLibs)	
				logger.info(Utils.indent() + "- # of lib versions (" + list.size() + ") is smaller than configured threshold (" + minNumberOfLibs + ") - ABORT!");
			
			return new ArrayList<LibProfile>();
		}
		
		
		// sort based on libname and libversion
		Collections.sort(list, LibProfile.comp);   
		return list;
	}
	
	
	private void printApiStats(LibApiRobustnessStats stats) {
		logger.info("- Stats: " + stats.lib + " |  version " +  stats.version + "  |  # newer versions: " + stats.newerVersions +  "  |  api-compatible with next version: "+ stats.apiCompatibleWithNextVersion());
		
		int publicAPIs = stats.getNumberOfPublicApis();
		int stablePublicAPIs = stats.getNumberOfStablePublicApis();
		logger.info(Utils.INDENT + "# of stable public APIs:  " + stablePublicAPIs + " / " + publicAPIs + " (" + MathUtils.computePercentage(stablePublicAPIs, publicAPIs) + "%)");

		if (publicAPIs != stablePublicAPIs) {
			logger.info(Utils.INDENT + "# of unstable public APIs: " + (publicAPIs - stablePublicAPIs) + "   min: " + stats.minApiCompatibleWithNextVersion());
			
		// print entries sorted by # compatible versions	
		stats.api2StableVersions.entrySet()
		    .stream()
		    .filter(e -> e.getValue() < stats.newerVersions)
		    .sorted(Map.Entry.comparingByValue(/*Collections.reverseOrder()*/))
		    .forEach(e -> printUnstableAPI(stats, e.getKey(), e.getValue()));
		}			
	}
	

	private void printUnstableAPI(LibApiRobustnessStats stats, String api, Integer maxVersions) {
		String maxVersionStr = getTargetVersion(stats.lib, stats.version, maxVersions);
		String maxVersionPlusOneStr = getTargetVersion(stats.lib, stats.version, maxVersions+1);
		
		logger.debug(Utils.INDENT2 + "- stable for " + maxVersions + "/" + stats.newerVersions 
				 + " versions (" + (maxVersionStr.equals(stats.version)? " --- " : "until " + maxVersionStr + " (next: " + maxVersionPlusOneStr + ")") + "): " + api);
		
		if (stats.api2CandidateApis.containsKey(api)) {  // api changed?
			for (String candidate: stats.api2CandidateApis.get(api))
				logger.debug(Utils.indent(3) + "- API changed?: " + candidate);
		}
	}

	
	/**
	 * For a given library version and a number of subsequent versions, retrieve the target version
	 * @param lib
	 * @param startVersion
	 * @param numberOfSubsequentVersions
	 * @return
	 */
	private String getTargetVersion(String lib, String startVersion, int numberOfSubsequentVersions) {
		List<String> sortedVersions;
		
		if (!sortedVersionsCache.containsKey(lib)) {
			sortedVersions = new ArrayList<String>();
			for (LibProfile lp: getSortedLibProfiles(lib, true)) {
				sortedVersions.add(lp.description.version);
			}
			sortedVersionsCache.put(lib, sortedVersions);
		}
	
		sortedVersions = sortedVersionsCache.get(lib);
		int idx = sortedVersions.indexOf(startVersion);
		
		if (idx > -1 && (idx+numberOfSubsequentVersions) < sortedVersions.size())
			return sortedVersions.get(idx+numberOfSubsequentVersions);
		else
			return null;
	}
}


//private List<LibProfile> getSortedLibProfiles(String libName, boolean skipBeta, boolean skipNoReleaseDate, int minNumberOfLibs) {
//	List<LibProfile> list = new ArrayList<LibProfile>();
//
//	// filter versions (non-final versions, versions without release data)
//	for (LibProfile lp: profiles) {
//		if (lp.description.name.equals(libName)) {
//			// if there is at least one version without release-date skip this library
//			if (lp.description.date == null && skipNoReleaseDate) {
//				logger.info(Utils.INDENT + "[getSortedLibProfiles] skip lib " + libName + " due to missing release dates!");
//				return new ArrayList<LibProfile>();
//			} else {
//				if (!lp.description.version.matches(".*[a-zA-Z]+.*") || !skipBeta)  // skip alpha/beta/rc ..
//					list.add(lp);
//			}
//		}
//	}
//	
//	// evaluate only if we have at least ten different versions of one lib
//	if (list.size() < minNumberOfLibs)
//		return new ArrayList<LibProfile>();
//
//	Collections.sort(list, LibProfile.comp);   // sort based on libname and libversion
//	return list;
//}

