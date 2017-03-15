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
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.github.zafarkhaja.semver.Version;

import de.infsec.tpl.eval.LibApiRobustnessStats;
import de.infsec.tpl.stats.ApiUsageSQLStats;
import de.infsec.tpl.stats.SQLStats;
import de.infsec.tpl.utils.MathUtils;
import de.infsec.tpl.utils.Utils;
import de.infsec.tpl.utils.VersionWrapper;


public class LibraryUpdatability {
	private static final Logger logger = LoggerFactory.getLogger(de.infsec.tpl.eval.LibraryUpdatability.class);

	// profile.id -> api usage stats
	private Map<Integer, AppApiUsage> profile2ApiUsage = new TreeMap<Integer, AppApiUsage>();

	// String(libname,libversion) -> stats
	private Map<String, LibApiRobustnessStats> lib2ApiStats;
	
	// LibName to set of ordered versions
	private Map<String, List<String>> lib2versions;

	private final int FLAG_NO_UPDATE = 0;                // no update possible without code changes
	private final int FLAG_UPDATE_TO_MAX = -1;           // indicates that lib can be updated to newest version
	private final int FLAG_NO_LIBSTATS_AVAILABLE = -2;   // no libstats available
	
	private int numberOfApps;
	
	
	private class AppApiUsage {
		public int profileId;
		public String libName;
		public String libVersion;
		public Set<String> apiUsed;
		
		// Indicates number of library versions that can be updated without code changes based on the actual API usage 
		// negative numbers have a special meaning, see FLAG_* constants, positive numbers denote max number of versions that can be updated
		public int stableVersions = FLAG_NO_LIBSTATS_AVAILABLE;   
		
		public AppApiUsage(int profileId, String libName, String libVersion) {
			this.profileId = profileId;
			this.libName = libName;
			this.libVersion = libVersion;
			this.apiUsed = new TreeSet<String>();
		}
	}

	
	
	
	public void run(File libraryApiDataFile, File apiUsageDbFile) {
		logger.info("= Library API eval =");

		// Load library API evoluation data and library API usage database from disk
		loadLibApiDataFromDisk(libraryApiDataFile); //new File("./libApiEval-libsecNEW.lstats"));//libApiEval_14.12.new.lstats")); //libApiEval_prof-14.12.lstats"));
		loadApiUsageFromDB(apiUsageDbFile); //new File("./appStats_libsec_usage.sqlite"));///databases/appStats-libusage-pm_06.01.2017.sqlite"));//appStats-libusage_20.12.2016.sqlite")); //./TEST.sqlite")); //./databases/appStats-libusage-pm_06.01.2017.sqlite"));//		

		// check how libraries in apps can be updated based on their API usage
		checkLibUpdatability();
		
		// check whether known vulnerabilities in libraries can be updated to first fixed version based on API usage
		checkSecurityVulnUpdatability();
		
		topUsedLibraryAPI();
	}
	
	
	

	@SuppressWarnings("unchecked")
	private void loadLibApiDataFromDisk(File statsFile) {
		logger.info("= Load library API robustness stats from file: " + statsFile);
		final int MIN_NR_LIBS = 10;
		lib2ApiStats = new HashMap<String, LibApiRobustnessStats>();
		
		// de-serialize lib api stats
		try {
			ArrayList<LibApiRobustnessStats> stats = (ArrayList<LibApiRobustnessStats>) Utils.disk2Object(statsFile);

			// mapping libraries to versions
			this.lib2versions = new TreeMap<String, List<String>>();
			for (LibApiRobustnessStats s: stats) {
				if (!lib2versions.containsKey(s.lib))
					lib2versions.put(s.lib, new ArrayList<String>());
				
				lib2versions.get(s.lib).add(s.version);
			}

			
			Set<String> excludedLibs = new HashSet<String>();  // exclude libs with less than MIN_NR_LIBS versions

			for (String lib: lib2versions.keySet()) {
				if (lib2versions.get(lib).size() < MIN_NR_LIBS) {
					excludedLibs.add(lib);
					logger.debug(" - exluded lib: " + lib + "  < " + MIN_NR_LIBS + " versions: " + lib2versions.get(lib));
				} else
					logger.trace(" # lib: " + lib + "   versions: " + lib2versions.get(lib));
			}
			
			for (LibApiRobustnessStats s: stats) {
				if (!excludedLibs.contains(s.lib)) {
					lib2ApiStats.put(s.lib + s.version, s);
				}
			}
					
		} catch (ClassNotFoundException e) {
			logger.error(Utils.stacktrace2Str(e));
		}
	}

	
	
	private void loadApiUsageFromDB(File dbFile) {
		logger.info("= Load app library usage from database: " + dbFile);
		
		// load the sqlite-JDBC driver using the current class loader
		try {
			Class.forName("org.sqlite.JDBC");
		} catch (ClassNotFoundException e) {
			logger.error("Could not load class org.sqlite.JDBC - skip creating DB");
			return;
		}

	    try (Connection con = DriverManager.getConnection("jdbc:sqlite:" + dbFile.getName())) {
	    	Statement stmt = con.createStatement();
	    
	    	// get unique lib names
	    	String query = "SELECT " + SQLStats.COL_NAME + " FROM " + SQLStats.T_LIBRARY + " GROUP BY " + SQLStats.COL_NAME + ";";
	    	Set<String> uniqueLibs = new TreeSet<String>();
	    	
	    	try (ResultSet rs = stmt.executeQuery(query)) {
	    		while (rs.next()) {
	    			uniqueLibs.add(rs.getString(1));
	    		}
	    	}
	    	
	    	numberOfApps = 0;
	    	query = "SELECT " + SQLStats.COL_APPID + " FROM " + SQLStats.T_PROFILE + " GROUP BY " + SQLStats.COL_APPID + ";";
	    	try (ResultSet rs = stmt.executeQuery(query)) {
	    		while (rs.next()) {
	    			numberOfApps++;
	    		}
	    	}
	    	
	    	logger.info(Utils.INDENT + "# unique libs: " + uniqueLibs.size());
	    	
			/*
			 *	 SELECT profiles.id,
			 *	        libraries.name,
			 *	        libraries.version,
			 *	        libapi.api
			 *	   FROM libraries,
			 *	        profiles,
			 *	        apiusage,
			 *	        libapi
			 *	  WHERE profiles.libId = libraries.id AND
			 *	        apiusage.apiId = libapi.id AND 
			 *	        apiusage.profileId = profiles.id AND 
	         *			libraries.name = "$LIBNAME"
	         *
	         *
			 *	  Result:  		
			 *		3	Gson	2.3.1	com.google.gson.GsonBuilder.setExclusionStrategies([Lcom.google.gson/ExclusionStrategy;)Lcom.google.gson/GsonBuilder;
			 *		3	Gson	2.3.1	com.google.gson.reflect.TypeToken.<init>()V
			 *		12	Gson	2.2	    com.google.gson.Gson.<init>()V
			 *		12	Gson	2.2	    com.google.gson.Gson.fromJson(Ljava/lang/String;Ljava/lang/Class;)Ljava/lang/Object;
			 */    		

    		// select all profiles and their api usage within the app
    		query = "SELECT " + SQLStats.T_PROFILE + "." + SQLStats.COL_APPID + ", "
    						  + SQLStats.T_PROFILE + "." + SQLStats.COL_ID + ", "  
							  + SQLStats.T_LIBRARY + "." + SQLStats.COL_NAME + ", "
							  + SQLStats.T_LIBRARY + "." + SQLStats.COL_VERSION + ", "
							  + ApiUsageSQLStats.T_LIBAPI + "." + ApiUsageSQLStats.COL_API + 
				     " FROM " + SQLStats.T_LIBRARY + ", " + SQLStats.T_PROFILE + ", " + ApiUsageSQLStats.T_APIUSAGE + ", " + ApiUsageSQLStats.T_LIBAPI + 
				    " WHERE " + SQLStats.T_PROFILE + "." + SQLStats.COL_LIBID + " = " + SQLStats.T_LIBRARY + "." + SQLStats.COL_ID + " AND "
				              + ApiUsageSQLStats.T_APIUSAGE + "." + ApiUsageSQLStats.COL_APIID + " = " + ApiUsageSQLStats.T_LIBAPI + "." + SQLStats.COL_ID + " AND "
				              + ApiUsageSQLStats.T_APIUSAGE + "." + ApiUsageSQLStats.COL_PROFILEID + " = " + SQLStats.T_PROFILE + "." + SQLStats.COL_ID + //" AND "
		//		              + SQLStats.T_LIBRARY  + "." + SQLStats.COL_NAME + " = " + Utils.quote(libName) + ";";
				              ";";

	    	try (ResultSet rs = stmt.executeQuery(query)) {
	    		while (rs.next()) {
	    			logger.trace(Utils.INDENT2 + "appid: " + rs.getInt(1) + "  pid: " + rs.getInt(2) +  " name: " + rs.getString(3) + " version: " + rs.getString(4) + "  api: " + rs.getString(5));

	    			if (!profile2ApiUsage.containsKey(rs.getInt(2))) {
	    				profile2ApiUsage.put(rs.getInt(2), new AppApiUsage(rs.getInt(2), rs.getString(3), rs.getString(4)));
	    			}
	    			
	    			profile2ApiUsage.get(rs.getInt(2)).apiUsed.add(rs.getString(5));
	    		}
	    	}
	    } catch (SQLException e) {
	    	logger.warn(Utils.stacktrace2Str(e));
	    }
		
	}

	

	
	

	// TODO What about lib lib dependencies?
	// TODO: general stats + grouped by category/lib
	private void checkLibUpdatability() {
		logger.info("= Check auto-update possibility for libraries =");
		
		// for each profile match
		for (int profileId: profile2ApiUsage.keySet()) {
			AppApiUsage usage = profile2ApiUsage.get(profileId);
			logger.debug("pid: " + usage.profileId + "  lib: " + usage.libName + " / " + usage.libVersion);
			
			if (lib2ApiStats.containsKey(usage.libName+usage.libVersion)) {
				LibApiRobustnessStats libstat = lib2ApiStats.get(usage.libName+usage.libVersion);
				usage.stableVersions = FLAG_UPDATE_TO_MAX;

				for (String api: usage.apiUsed) {
					
					if (!libstat.api2StableVersions.keySet().contains(api)) {
						logger.debug("      > Couldn't lookup used api: " + api + "    [protected?]");
						continue;
					}
					
					if (libstat.isApiStable(api))
						logger.debug(Utils.INDENT + "- api used: " + api + "  [stable]");
					else {
						logger.debug(Utils.INDENT + "- api used: " + api + "  stable for " + libstat.api2StableVersions.get(api) + "  newerVersions: " + libstat.newerVersions);
						if (libstat.api2CandidateApis.containsKey(api))
							logger.debug(Utils.INDENT + "- candidate: " + libstat.api2CandidateApis.get(api));
						
						if (usage.stableVersions == FLAG_UPDATE_TO_MAX || libstat.api2StableVersions.get(api) < usage.stableVersions) 
							usage.stableVersions = libstat.api2StableVersions.get(api);
					}
					
				}
				
				logger.debug("");
				if (usage.stableVersions != FLAG_UPDATE_TO_MAX) {
					logger.debug(Utils.INDENT + "=> Lib " + usage.libName + "  version: " + usage.libVersion + "  can be updated by " + usage.stableVersions + " versions");
				} else
					logger.debug(Utils.INDENT + "=> Lib " + usage.libName + "  version: " + usage.libVersion + "  can be updated to latest version");
						
			} else {
				logger.debug(Utils.INDENT + "No stats for " + usage.libName + " - " + usage.libVersion);
			}
			logger.debug("");
		}
		

		logger.info("= Report =");
		int maxUpdate = 0;
		int noLibApiInfoAv = 0;
		int noUpdate = 0;
		
		for (AppApiUsage usage: profile2ApiUsage.values()) {
			if (usage.stableVersions == FLAG_UPDATE_TO_MAX)
				maxUpdate++;
			else if (usage.stableVersions == FLAG_NO_LIBSTATS_AVAILABLE)
				noLibApiInfoAv++;
			else if (usage.stableVersions == FLAG_NO_UPDATE)
				noUpdate++;
		}
		
		logger.info(Utils.INDENT + maxUpdate + " / " + (profile2ApiUsage.size()-noLibApiInfoAv) + " (" + MathUtils.computePercentage(maxUpdate, profile2ApiUsage.size()-noLibApiInfoAv) + "%) can be upgraded to newest version");
		
// TODO:  for those that can be upgraded partially, how many of them can't be upgraded fully due to major version changes?
		
		logger.info(Utils.INDENT + noUpdate + " / " + (profile2ApiUsage.size()-noLibApiInfoAv) + " (" + MathUtils.computePercentage(noUpdate, profile2ApiUsage.size()-noLibApiInfoAv) + "%) can't be updated at all");
		logger.info(Utils.INDENT + "No lib API information available for " + noLibApiInfoAv + " / " + profile2ApiUsage.size() + " (" + MathUtils.computePercentage(noLibApiInfoAv, profile2ApiUsage.size()) + "%) [Release dates missing]");
		logger.info("");
		
		logger.info("Updatability by library (update to newest version)");
		Map<String,Integer> lib2UsageCount = new HashMap<String,Integer>();
		Map<String,Integer> lib2UpdatabilityCount = new HashMap<String,Integer>();
		
		for (AppApiUsage usage: profile2ApiUsage.values()) {
			if (usage.stableVersions == FLAG_NO_LIBSTATS_AVAILABLE) continue;
			
			if (!lib2UsageCount.containsKey(usage.libName)) {
				lib2UsageCount.put(usage.libName, 0);
				lib2UpdatabilityCount.put(usage.libName, 0);
			}
			
			lib2UsageCount.put(usage.libName, lib2UsageCount.get(usage.libName)+1);
			if (usage.stableVersions == FLAG_UPDATE_TO_MAX)
				lib2UpdatabilityCount.put(usage.libName, lib2UpdatabilityCount.get(usage.libName)+1);
		}
		
		// report
		lib2UpdatabilityCount.entrySet().stream()
			.sorted((e1, e2) -> ((Float) MathUtils.computePercentage(e2.getValue(), lib2UsageCount.get(e2.getKey()))).compareTo(((Float) MathUtils.computePercentage(e1.getValue(), lib2UsageCount.get(e1.getKey())))))
        	.forEach(e -> logger.info(Utils.INDENT + "- Library: " + e.getKey() + "  updatable in: " + e.getValue() + "/" + lib2UsageCount.get(e.getKey()) + " (" + MathUtils.computePercentage(e.getValue(), lib2UsageCount.get(e.getKey())) + "%)"));
	}



	
	private void checkSecurityVulnUpdatability() {
		logger.info("");
		logger.info("Security Vulnerability fixing");

		HashMap<String, TreeSet<Version>> orderedLibs2Version = new HashMap<String, TreeSet<Version>>();
		for (String k: lib2versions.keySet()) {
			
			TreeSet<Version> ordered = new TreeSet<Version>();
			for (String v: lib2versions.get(k))
				ordered.add(VersionWrapper.valueOf(v));
			
			orderedLibs2Version.put(k, ordered);
		}

		/*
		 * specification of vulnerable library versions
		 */
		final List<String> LIB_NAMES = new ArrayList<String>();
		final List<Version> LIB_START_VER = new ArrayList<Version>();
		final List<Version> LIB_END_VER = new ArrayList<Version>();

		//	Supersonic 5.14 - 6.3.4   (5.14  6.0.0  6.1.0  6.1.1  6.2.0  6.2.1  6.2.2  6.3.0  6.3.1  6.3.2  6.3.3  6.3.4)
		LIB_NAMES.add("Supersonic");
		LIB_START_VER.add(VersionWrapper.valueOf("5.14"));
		LIB_END_VER.add(VersionWrapper.valueOf("6.3.4"));

		//  MoPub      3.10 - 4.3     (3.10.0  3.11.0  3.12.0  3.13.0  4.0.0  4.1.0  4.2.0  4.3.0)
		LIB_NAMES.add("MoPub");
		LIB_START_VER.add(VersionWrapper.valueOf("3.10"));  
		LIB_END_VER.add(VersionWrapper.valueOf("4.3"));

		//  Dropbox  1.5.4 - 1.6.1    (1.5.4, 1.6, 1.6.1)
		LIB_NAMES.add("Dropbox");      		
		LIB_START_VER.add(VersionWrapper.valueOf("1.5.4"));  
		LIB_END_VER.add(VersionWrapper.valueOf("1.6.1"));    

		//  Facebook 3.15.0
		LIB_NAMES.add("Facebook");      		
		LIB_START_VER.add(VersionWrapper.valueOf("3.15.0"));  
		LIB_END_VER.add(VersionWrapper.valueOf("3.15.0"));
		
		//  Airpush < 8.0.0  (we are currently only check for 8.0.0)
		LIB_NAMES.add("Airpush");      		
		LIB_START_VER.add(VersionWrapper.valueOf("8.0.0"));  
		LIB_END_VER.add(VersionWrapper.valueOf("8.0.0"));
		
		//  Vungle 	3.1.0 - 3.2.2  (3.1.0, 3.1.1, 3.2.0, 3.2.1, 3.2.2)    (we are currently only checking for 3.2.2)
		LIB_NAMES.add("Vungle");      		
		LIB_START_VER.add(VersionWrapper.valueOf("3.2.2"));  
		LIB_END_VER.add(VersionWrapper.valueOf("3.2.2"));

		
		// Key is LIBNAME_LIBVERSION,  value is list of: [update2Fix possible, max update possible,  no update possible, lib usage count]
		HashMap<String, ArrayList<Integer>> vulnerabilityStats = new HashMap<String, ArrayList<Integer>>();
		
		for (AppApiUsage usage: profile2ApiUsage.values()) {
			try {
				final Version curVersion = VersionWrapper.valueOf(usage.libVersion);

				// check for all libraries and vulnerability ranges
				for (int i = 0; i < LIB_NAMES.size(); i++) {
					if (usage.libName.equals(LIB_NAMES.get(i)) && curVersion.greaterThanOrEqualTo(LIB_START_VER.get(i)) && curVersion.lessThanOrEqualTo(LIB_END_VER.get(i))) {
						String key = LIB_NAMES.get(i) + "_" + curVersion.toString();
						if (!vulnerabilityStats.containsKey(key))
							vulnerabilityStats.put(key, new ArrayList<Integer>(Arrays.asList(0,0,0,0)));  // update2Fix possible, max update possible,  no update possible, lib usage count
						
						ArrayList<Integer> stats = vulnerabilityStats.get(key);
						stats.set(3, stats.get(3)+1);  // increase usage count
						
						if (usage.stableVersions == FLAG_UPDATE_TO_MAX)
							stats.set(1, stats.get(1)+1);
						else if (usage.stableVersions == FLAG_NO_UPDATE)
							stats.set(2, stats.get(2)+1);
						else {
							Version updatableVersion = lookupLibVersion(orderedLibs2Version.get(usage.libName), curVersion, usage.stableVersions);
							if (updatableVersion != null && updatableVersion.greaterThan(LIB_END_VER.get(i)))
								stats.set(0, stats.get(0)+1);	
						}
					}
				}
			} catch (Exception e) { /**/ }
		}

		// report results
		for (String lib: vulnerabilityStats.keySet()) {
			ArrayList<Integer> stats = vulnerabilityStats.get(lib);
			logger.info("- " + lib + "  (" + stats.get(3) + "):  update2Fix: " + (stats.get(0)+stats.get(1)) + "  (update2max: " + stats.get(1) + ")  NO_UPDATE: " + stats.get(2));
		}

	}

	
	
	

	// hotspot per lib
	// ranking incl. percentage (used by apps that incl that lib)
	// check stability in lib api usage (if available), how many changes in how many versions
	
	public class LibApiHotspots {
		String libName;
		Integer libUsageCount;           // usage count of library
		Map<String, Integer> api2Count;  // usage count per API
		ArrayList<Integer> usageCounts;  // for each profile, number of used APIs
		
		public LibApiHotspots(String libName) {
			this.libName = libName;
			this.libUsageCount = 0;
			this.api2Count = new HashMap<String, Integer>();
			this.usageCounts = new ArrayList<Integer>();
		}
		
		public void update(Collection<String> usedApis) {
			this.libUsageCount++;
			
			for (String api: usedApis) {
				if (!api2Count.containsKey(api))
					api2Count.put(api, 0);
				api2Count.put(api, api2Count.get(api)+1);
			}
			
			usageCounts.add(usedApis.size());
		}
	}
	
	
	private void topUsedLibraryAPI() {
		logger.info("= Check top used API per lib (hotspots) =");
		HashMap<String, LibApiHotspots> hotspots = new HashMap<String, LibApiHotspots>();
				
		for (AppApiUsage usage: profile2ApiUsage.values()) {
			if (!hotspots.containsKey(usage.libName))
				hotspots.put(usage.libName, new LibApiHotspots(usage.libName));
			
			hotspots.get(usage.libName).update(usage.apiUsed);
		}

		int allLibApiUsage = 0;
		
		for (LibApiHotspots h: hotspots.values()) {
			String noOfVersions = lib2versions.containsKey(h.libName) ? "(# " + lib2versions.get(h.libName).size() + " versions)": "(N/A)";
						
			int countAll = 0;
			for (int c: h.usageCounts) countAll += c;
			allLibApiUsage += countAll;
			
			logger.info("- Library: " + h.libName +
					    " " + noOfVersions + "  used by: " + h.libUsageCount + "/" + numberOfApps + " apps  (" + MathUtils.computePercentage(h.libUsageCount, numberOfApps) + "%)" +
					    "  avg APIs used: " + ((float)countAll/(float)h.libUsageCount) + "  median APIs used: " + MathUtils.medianInt(h.usageCounts));
			
			// print top 10 apis
			logger.info(Utils.INDENT + "Top10 APIs");
			h.api2Count.entrySet().stream()
				.sorted(Map.Entry.<String, Integer>comparingByValue().reversed())
			    .limit(10)
			    .forEach(e -> logger.info(Utils.INDENT + "used by: " + e.getValue() + "/" + h.libUsageCount + "  (" + MathUtils.computePercentage(e.getValue(), h.libUsageCount) + "%)   api: " + e.getKey() + "  " + apiStability(h.libName, e.getKey())));
			
			// TODO: or count the number of unused apis
			logger.info(Utils.INDENT + "Flop10 APIs");
			h.api2Count.entrySet().stream()
			    .sorted(Map.Entry.<String, Integer>comparingByValue())
			    .limit(10)
			    .forEach(e -> logger.info(Utils.INDENT + "used by: " + e.getValue() + "/" + h.libUsageCount + "  (" + MathUtils.computePercentage(e.getValue(), h.libUsageCount) + "%)   api: " + e.getKey() + "  " + apiStability(h.libName, e.getKey())));
			
			
			logger.info("");
			
			// number of api used on average per lib  / in relation to av. pub api
			//      - in total

		}
		
		logger.info("All lib API usage: " + allLibApiUsage + "  number of libs: " + profile2ApiUsage.size() + "  overall avg: " + ((float)allLibApiUsage/(float)profile2ApiUsage.size()));
	}
	
	
	
	private String apiStability(String libName, String api) {
		int stable = 0;
		int notStable = 0;
		int notExisting = 0;
		boolean found = false;
				
		for (LibApiRobustnessStats stats: lib2ApiStats.values()) {
			if (stats.lib.equals(libName)) {
				found = true;
				int status = stats.isApiStableOrExisting(api);
				
				if (status == -1) {
					notExisting++;
				} else if (status == 0) {
					notStable++;
				} else
					stable++;
			}
		}
		
		if (!found || notExisting == lib2versions.get(libName).size())  // protected?
			return "";
		
		StringBuilder sb = new StringBuilder();
		if (notExisting > 0)
			sb.append("not existing: " + notExisting);
		if (stable > 0)
			sb.append("  stable in: " + stable);
		if (notStable > 0)
			sb.append(" not stable: " + notStable);
		
		return sb.toString();
	}

	

	private Version lookupLibVersion(Set<Version> orderedVersions, Version startVersion, int newerVersions) {
//	logger.info("libname: " + libName + "  start: " + startVersion + "  newer: " + newerVersions);
		List<Version> orderedList = new ArrayList<Version>(orderedVersions);
			
		if (orderedList.contains(startVersion)) {
			if (orderedList.indexOf(startVersion) + newerVersions < orderedList.size())
				return orderedList.get(orderedList.indexOf(startVersion) + newerVersions); 
			else
				logger.warn("Version list size: " + orderedList.size() + " <  access index: " + (orderedList.indexOf(startVersion) + newerVersions));
		} else {
			logger.warn("Version: " + startVersion + " is not in list.");
		}

		return null;
	}
}

