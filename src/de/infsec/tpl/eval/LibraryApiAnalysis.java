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
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import de.infsec.tpl.config.LibScoutConfig;
import de.infsec.tpl.hash.HashTreeOLD;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.infsec.tpl.hash.AccessFlags;
import de.infsec.tpl.profile.LibProfile;
import de.infsec.tpl.utils.MathUtils;
import de.infsec.tpl.utils.Utils;
import de.infsec.tpl.utils.VersionWrapper;
import org.slf4j.MDC;


/**
 * Library API robustness analysis
 *
 * Check how subsequent library versions differ in their public API, i.e.
 * are public APIs removed, modified, and/or added
 * For each library a {@link LibApiRobustnessStats} is created that tracks APIs across versions
 * The results are written in the configured json directory and logged.
 *
 * @deprecated
 */

public class LibraryApiAnalysis {
	private static final Logger logger = LoggerFactory.getLogger(de.infsec.tpl.eval.LibraryApiAnalysis.class);

	private static List<LibProfile> profiles; 
	private static Map<String, List<String>> report;
	
	// Library name to percentage of correct semver values, e.g. Admob -> 35.1%
	private static Map<String, Float> libSemverValues = new HashMap<String, Float>();
	

	// expected|real count per lib how often patch|minor|major version occur
	HashMap<String,Integer> semverExpChangeCountGlobal = new HashMap<String,Integer>() {{
		put("patch", 0); put("minor", 0); put("major", 0);
	}};
	HashMap<String,Integer> semverRealChangeCountGlobal = new HashMap<String,Integer>() {{
		put("patch", 0); put("minor", 0); put("major", 0);
	}};

	private HashMap<String, Integer> semVerInconsistenciesGlobal = new HashMap<String, Integer>();
	
	private ArrayList<LibApiRobustnessStats> libStats = new ArrayList<LibApiRobustnessStats>();

	// only libraries with a minimum amount of versions are analyzed
	private final int MIN_NUMBER_OF_LIBRARY_PROFILES = 10;


	public LibraryApiAnalysis() {
		// set identifier for logging
		String logIdentifier = LibScoutConfig.logDir.getAbsolutePath() + File.separator + "libApiAnalysis";
		MDC.put("appPath", logIdentifier);
	}


	/**
	 * Runs the library api robustness analysis
	 * NOTE: This requires profiles built with TRACE verboseness and public only filter
	 * @param libProfiles  a list of {@link LibProfile} with TRACE verboseness and public-only methods
	 */
	public void run(List<LibProfile> libProfiles) {
		profiles = libProfiles;
		
		if (profiles == null || profiles.isEmpty()) {
			logger.info("Empty profile list - Abort");
		    return;
		}
	
		TreeSet<String> uniqueLibraries = new TreeSet<String>(LibProfile.getUniqueLibraries(profiles).keySet());

		logger.info("= Evaluate libraries =");
		logger.info(Utils.INDENT + "Loaded " + profiles.size() + " library profiles for " + uniqueLibraries.size() + " distinct libraries");

		logger.info("- Evaluate public library API -");

		final String[] semVerKeys = new String[]{"patch->major", "minor->major", "patch->minor", "minor->patch", "major->patch", "major->minor" };  // sorted by severity desc
		for (String k: semVerKeys)
			semVerInconsistenciesGlobal.put(k, 0);

		report = new HashMap<String, List<String>>();

		for (String libName: uniqueLibraries) {
			logger.info("= Check lib: " + libName + " =");
			List<LibProfile> list = getSortedLibProfiles(libName, null, true, false, MIN_NUMBER_OF_LIBRARY_PROFILES);
			
			if (list.isEmpty()) {
				continue;
			}

			logger.info(Utils.INDENT + "# versions: " + list.size());
			checkPublicAPI(list);

			LibApiRobustnessStats stats = checkPerApiRobustness(libName, list);
			if (stats != null)
				libStats.add(stats);
		}

		// print results
		printResults(uniqueLibraries, semVerKeys);

		// serialize to disk
	//	Utils.object2Disk(new File("./libApiData.lstats"), libStats);

		// output results in json format
		for (LibApiRobustnessStats stats: libStats) {
			File jsonOutputFile = new File(LibScoutConfig.jsonDir + File.separator + "lib-api-analysis" + File.separator + stats.libName + ".json");
			try {
				Utils.obj2JsonFile(jsonOutputFile, stats);
			} catch (IOException e) {
				logger.warn("Could not write json results: " + Utils.stacktrace2Str(e));
			}
		}
	}

	
	
	
	
	/**
	 * Checks for each <library, version> the stableness of each declared public API, i.e.
	 * for each public API determine the highest library version for which this exact API is available 
	 * @param libName   name of the library
	 * @param profiles  of {@link LibProfile} to check
	 * @return  a {@link LibApiRobustnessStats} or null if there are too few lib versions 
	 */
	private LibApiRobustnessStats checkPerApiRobustness(String libName, List<LibProfile> profiles) {
		LibApiRobustnessStats aStats = new LibApiRobustnessStats(libName);
		
		for (LibProfile lp: profiles) {
			// version -> # of pub APIs
			aStats.versions2pubApiCount.put(lp.description.version, lp.hashTreeOLDS.iterator().next().getAllMethodSignatures().size());
			
			// for each public API
			for (String sig: lp.hashTreeOLDS.iterator().next().getAllMethodSignatures()) {
				aStats.updateApi(sig, lp.description.version);
			}
		}

		// for each api determine last version, check if last version = overall last version, if not search for candidates in last version +1
		String lastLibVersion = profiles.get(profiles.size()-1).description.version;
		
		for (String api: aStats.api2Versions.keySet()) {
			String lastVersion = aStats.api2Versions.get(api).get(aStats.api2Versions.get(api).size()-1);
			
			// check if last library version that includes this api is last lib version in database
			if (!lastVersion.equals(lastLibVersion)) {
				LibProfile lastLibProfile = getTargetLibProfile(profiles, lastLibVersion, 0);
				LibProfile sucLibProfile = getTargetLibProfile(profiles, lastVersion, 1);

				// check for alternative candidates,
				// currently it is checked whether there are APIs with the same class/method name but different arg/return types
//TODO: collect stats about replacements, classify replacements
//TODO: do advanced check whether and how changed api could still be stable (classhierarchy check for arg|ret types (super types?)
//TODO: check candidates also by fixed selector but different name?

				List<String> apiList = sucLibProfile.hashTreeOLDS.iterator().next().getAllMethodSignatures();
				String methodName = api.substring(0, api.indexOf("("));

				for (String alternativeApi: apiList) {
					if (alternativeApi.startsWith(methodName) &&
						!lastLibProfile.hashTreeOLDS.iterator().next().getAllMethodSignatures().contains(alternativeApi)) {  // print only if it's an API that was not in the former lib version

						aStats.updateCandidateApi(api, alternativeApi);
					}
				}
			}
		}
		
		return aStats;
	}

	
	/**
	 * For a given library version and a number of subsequent versions, retrieve the target version
	 * @param profiles  of {@link LibProfile} to check
	 * @param startVersion
	 * @param numberOfSubsequentVersions
	 * @return  The identified {@link LibProfile} or null if no matching profile was found
	 */
	private LibProfile getTargetLibProfile(List<LibProfile> profiles, String startVersion, int numberOfSubsequentVersions) {
		for (int i = 0; i < profiles.size(); i++) {
			LibProfile profile = profiles.get(i);
			if (profile.description.version.equals(startVersion)) {
				if ((i + numberOfSubsequentVersions) < profiles.size()) {
					return profiles.get(i + numberOfSubsequentVersions);
				} else {
					logger.debug(Utils.INDENT + "Access out of bounds: index: " + i + " numberOfSubsequentVersions: " + numberOfSubsequentVersions + "  # profiles: " + profiles.size());
				    return null;
				}
			}
		}
		
		if (!profiles.isEmpty())
			logger.debug(Utils.INDENT + "Version " + startVersion + " was not found for library " + profiles.get(0).description.name);

		return null;
	}
	
		
	
	
	/**
	 * Old unspecific API robustness check (checks whether *all* public API methods are included in next version).
	 * Moreover determines expected and actual SemVer based on API diffs	
	 * @param profiles  of {@link LibProfile} to check
	 */
	private void checkPublicAPI(List<LibProfile> profiles) {
				
		String cat = profiles.get(0).description.category.toString();
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
		
		for (int i = 0; i < profiles.size(); i++) {
			LibProfile lp1 = profiles.get(i);
			HashTreeOLD pubTree1 = HashTreeOLD.getTreeByConfig(lp1.hashTreeOLDS, false, AccessFlags.getPublicOnlyFilter(), false);
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
				LibProfile lp0 = profiles.get(i-1);
				HashTreeOLD pubTree0 = HashTreeOLD.getTreeByConfig(lp0.hashTreeOLDS, false, AccessFlags.getPublicOnlyFilter(), false);
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
		logger.info("  ==>  average API diff: " + (avgDiff / (float) profiles.size()) + "  api compatible: " + apiCompatibleCount + "/" + profiles.size() + " (" + MathUtils.computePercentage(apiCompatibleCount, profiles.size())  + "%)");
		
		// change count
		logger.info("  ==> version change classification: ");
		logger.info("     [expected change count] patch: " + semverExpChangeCountLib.get("patch") + "   minor:  " + semverExpChangeCountLib.get("minor") + "   major: " + semverExpChangeCountLib.get("major"));
		logger.info("     [    real change count] patch: " + semverRealChangeCountLib.get("patch") + "   minor:  " + semverRealChangeCountLib.get("minor") + "   major: " + semverRealChangeCountLib.get("major"));
		
		logger.info("  ==>  SemVer correct: " + semVerCorrect + "/" + (profiles.size()-1) + " (" + MathUtils.computePercentage(semVerCorrect, profiles.size()-1) + "%)");
		for (String key: semVerKeys) {
			logger.info("       =>  SemVer inconsistencies (expected->real): " + key + "  : " + semVerInconsistencies.get(key) + "/" + (profiles.size() - 1 - semVerCorrect) + "  (" + MathUtils.computePercentage(semVerInconsistencies.get(key), (profiles.size() -1 - semVerCorrect)) + "%)");
			semVerInconsistenciesGlobal.put(key, semVerInconsistenciesGlobal.get(key) + semVerInconsistencies.get(key));
		}
	
		logger.info("");
		
		report.get(cat).add(Utils.INDENT + "# " + profiles.get(0).description.name + " (" + profiles.get(0).description.category + ")");
		report.get(cat).add(Utils.INDENT2 + "- average API diff: " + (avgDiff / (float) profiles.size()) + "  api compatible: " + apiCompatibleCount + "/" + profiles.size() + " (" + MathUtils.computePercentage(apiCompatibleCount, profiles.size())  + "%)");
		
		float semverCorrectPer = MathUtils.computePercentage(semVerCorrect, profiles.size());
		report.get(cat).add(Utils.INDENT2 + "- SemVer correct: " + semVerCorrect + "/" + profiles.size() + " (" + semverCorrectPer + "%)");

		
		libSemverValues.put(profiles.get(0).description.name, semverCorrectPer);
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
		
		int numberOfAnalyzedLibs = libStats.size();
		long semver80plusCount = libSemverValues.values().stream().filter(f -> f.floatValue() > 80f).count();
		logger.info("SemVer correct > 80%: " + semver80plusCount + " / " + numberOfAnalyzedLibs + "  (" + MathUtils.computePercentage(semver80plusCount, numberOfAnalyzedLibs) + "%)");
		
		long semver20MinusCount = libSemverValues.values().stream().filter(f -> f.floatValue() < 20f).count();
		logger.info("SemVer correct < 20%: " + semver20MinusCount + " / " + numberOfAnalyzedLibs + "  (" + MathUtils.computePercentage(semver20MinusCount, numberOfAnalyzedLibs) + "%)");
		
		logger.info("Libraries with top/flop SemVer adherence:");
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

		
		if (logger.isDebugEnabled()) {
			logger.debug(""); logger.debug("");
			logger.debug("# Per-Lib-API robustness analysis #");
			
			for (LibApiRobustnessStats stats: libStats) {
				printApiStats(stats);
				logger.debug("");
			}
		}
	}
	
	
	
	/**
	 * Works like {@link #getSortedLibProfiles(String, boolean, boolean, int) with preset skipNoReleaseDate and minNumberOfLibs.
	 * @param libname
	 * @param skipBeta  true, if rc, alpha, beta versions are to be filtered
 	 * @return a sorted list of {@link LibProfile}
	 */
	private List<LibProfile> getSortedLibProfiles(String libName, boolean skipBeta) {
		return getSortedLibProfiles(libName, skipBeta, false, MIN_NUMBER_OF_LIBRARY_PROFILES);
	}


	/**
	 * Works like {@link #getSortedLibProfiles(String, String, boolean, boolean, int). No startVersion is provided here.
	 * @param libname
	 * @param skipBeta  true, if rc, alpha, beta versions are to be filtered
	 * @param skipNoReleaseDate   if true, version with no release date are skipped 
	 * @param minNumberOfLibs  return an empty list of there are less versions available
	 * @return a sorted list of {@link LibProfile}
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
			else if (list.size() < minNumberOfLibs)
				logger.info(Utils.indent() + "- # of lib versions (" + list.size() + ") is smaller than configured threshold (" + minNumberOfLibs + ") - ABORT!");
	
			logger.info("");
			return new ArrayList<LibProfile>();
		}
		
		
		// sort based on libname and libversion
		Collections.sort(list, LibProfile.comp);   
		return list;
	}

	
	private void printApiStats(LibApiRobustnessStats stats) {
		logger.debug("- Stats: " + stats.libName + " |  # versions " +  stats.versions2pubApiCount.size());
		
		for (String version: stats.versions2pubApiCount.keySet()) {
			logger.debug(Utils.INDENT + "- version: " + version + "   # newer versions: " + stats.getNumberOfNewerVersions(version) + "  # API-compatible suc Versions: " + stats.getNumberOfApiCompatibleVersions(version));
			logger.debug(Utils.INDENT2 + "# pub APIs: " + stats.versions2pubApiCount.get(version));
			
			int publicAPIs = stats.getNumberOfPublicApis(version);
			int stablePublicAPIs = stats.getNumberOfStablePublicApis(version);
			logger.debug(Utils.indent(3) + "# of stable public APIs:  " + stablePublicAPIs + " / " + publicAPIs + " (" + MathUtils.computePercentage(stablePublicAPIs, publicAPIs) + "%)");

			if (publicAPIs != stablePublicAPIs) 
				logger.debug(Utils.indent(3) + "# of unstable public APIs: " + (publicAPIs - stablePublicAPIs));

			if (logger.isTraceEnabled()) {
				stats.api2Versions.entrySet().stream()
					.filter(e -> !stats.isApiStable(e.getKey(), version))
					.forEach(e -> printUnstableApi(stats, version, e.getKey()));
			}
		}
	}

	
	private void printUnstableApi(LibApiRobustnessStats stats, String version, String api) {
		int numberVersionsApi = stats.getNumberOfStableVersions(api, version);
		String maxVersionApi = stats.getLatestVersionWithApi(api, version);
		String maxVersionApiSuc = stats.getLatestVersionWithApi(api, version, true);
		
		logger.trace(Utils.INDENT2 + "- stable for " + numberVersionsApi + "/" + stats.getNumberOfNewerVersions(version) 
				 + " versions (last version: " + maxVersionApi + "   next version: " + maxVersionApiSuc + "):  " + api); 
		
		if (stats.api2CandidateApis.containsKey(api)) {  // api changed?
			for (String candidate: stats.api2CandidateApis.get(api))
				logger.trace(Utils.indent(3) + "- API changed?: " + candidate);
		}
	}

}
