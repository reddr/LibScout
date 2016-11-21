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

import java.io.File;
import java.io.IOException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.infsec.tpl.TplCLI;
import de.infsec.tpl.TplCLI.CliOptions;
import de.infsec.tpl.hash.Hash;
import de.infsec.tpl.hash.HashTree;
import de.infsec.tpl.profile.LibProfile;
import de.infsec.tpl.profile.SerializableProfileMatch;
import de.infsec.tpl.utils.Pair;
import de.infsec.tpl.utils.Utils;


public class SQLStats {
	private static final Logger logger = LoggerFactory.getLogger(de.infsec.tpl.stats.SQLStats.class);

	public static final File DB_FILE = new File("appStats.sqlite");
	
	// library table
	public static final String T_LIBRARY = "libraries";
	public static final String COL_CATEGORY = "category";
	public static final String COL_RELEASEDATE = "releaseDate";
	public static final String COL_LIB_PACKAGES = "libPackages";
	public static final String COL_LIB_CLASSES = "libClasses";
	public static final String COL_LIB_METHODS = "libMethods";
	public static final String COL_ROOT_PACKAGE = "rootPackage";
	public static final String COL_HTREE_MIN_HASH = "htreeMinHash";
	public static final String COL_HTREE_PUBONLY_HASH = "htreePubOnlyHash";
	public static final String COL_HTREE_MAX_HASH  = "htreeMaxHash";
	
	// application table
	public static final String T_APPLICATION = "apps";
	public static final String COL_SHAREDUID = "sharedUid";
	public static final String COL_APP_PACKAGES = "appPackages";
	public static final String COL_APP_CLASSES = "appClasses";
	public static final String COL_PROCESSING_TIME = "processingTime";

	// profile table
	public static final String T_PROFILE = "profiles";
	public static final String COL_LIBID = "libId";
	public static final String COL_APPID = "appId";
	public static final String COL_MATCHLEVEL = "matchLevel";
	public static final String COL_ISOBFUSCATED = "isObfuscated";
	public static final String COL_ROOTPCKG_PRESENT = "rootPckgPresent";
	public static final String COL_SIMSCORE = "simScore";
	public static final String COL_MATCH_CONF_MIN = "matchConfMin";
	public static final String COL_MATCH_CONF_PUBONLY = "matchConfPubOnly";
	public static final String COL_MATCH_CONF_MAX = "matchConfMax";

	// lib package match table
	public static final String T_PACKAGE_MATCH = "pckgmatch";
	public static final String COL_LIBNAME = "libname";
	
	// shared columns
	public static final String COL_ID = "id";
	public static final String COL_NAME = "name";
	public static final String COL_VERSION = "version";

	
	
	public static void stats2DB(List<LibProfile> profiles) {
		try {
			logger.info("Generate DB from stats mode!");
			logger.info(Utils.INDENT + "Loaded " + profiles.size() + " profiles from disk");
			List<SerializableAppStats> appStats = loadAppStats(CliOptions.statsDir);
			generateDB(profiles, appStats);
		} catch (Exception e) {
			logger.error(Utils.stacktrace2Str(e));
			System.exit(1);
		}
	}
	
	
	public static List<SerializableAppStats> loadAppStats(File dir) throws ClassNotFoundException, IOException {
		// de-serialize app stats
		long s = System.currentTimeMillis();
		List<SerializableAppStats> appStats = new ArrayList<SerializableAppStats>();
		for (File f: Utils.collectFiles(dir, new String[]{"data"})) {
			SerializableAppStats ap = (SerializableAppStats) Utils.deSerializeObjectFromDisk(f);
			appStats.add(ap);
		}
		
		logger.info(Utils.INDENT + "Loaded " + appStats.size() + " app stats from disk (in " + Utils.millisecondsToFormattedTime(System.currentTimeMillis() - s) + ")");
		logger.info("");
		
		return appStats;
	}


	public static void generateDB(List<LibProfile> profiles, List<SerializableAppStats> appStats) {
	    // load the sqlite-JDBC driver using the current class loader
		try {
			Class.forName("org.sqlite.JDBC");
		} catch (ClassNotFoundException e) {
			logger.error("Could not load class org.sqlite.JDBC - skip creating DB");
			return;
		}

	    Connection connection = null;
	    try {
	    	File dbFile = DB_FILE; // TODO: make configurable
	    	
	    	if (dbFile.exists())
	    		logger.warn("DB file " + DB_FILE + " exists! -- No updates will be performed - Abort!");
	    	else {
		    	// create a database connection
				connection = DriverManager.getConnection("jdbc:sqlite:" + dbFile.getName());
				
				createDB(connection);
				updateDB(connection, profiles, appStats);
	    	}

	    } catch(SQLException e) {
	    	logger.warn(Utils.stacktrace2Str(e));
	    } finally {
	    	try {
		        if (connection != null)
		          connection.close();
	    	} catch (SQLException e) {
	    		// connection close failed.
		    	logger.warn(Utils.stacktrace2Str(e));
	    	}
	    }	
	}
	
	
	private static void createDB(Connection con) throws SQLException {
		logger.info("Create Database..");
		
		Statement stmt = con.createStatement();
		stmt.setQueryTimeout(30);  // set timeout to 30 sec.

		// create library description table
		String sql = "CREATE TABLE IF NOT EXISTS " + T_LIBRARY +  "(" +
			COL_ID + " INTEGER, " +
			COL_NAME + " VARCHAR(255) not NULL, " +         // library name
			COL_CATEGORY + " VARCHAR(255) not NULL, " +     // one of:  Advertising, Analytics, Android, Tracker, SocialMedia, Cloud, Utilities
			COL_VERSION + " VARCHAR(255) not NULL, " +      // library version
			COL_RELEASEDATE + " INTEGER not NULL, " +       // long milliseconds since beginning
			COL_LIB_PACKAGES + " INTEGER not NULL, " +      // number of non-empty lib packages
			COL_LIB_CLASSES + " INTEGER not NULL, " +       // number of lib classes
			COL_LIB_METHODS + " INTEGER, " +                // number of lib methods
			COL_ROOT_PACKAGE + " VARCHAR(255), " +          // library root package, might be null if ambigious
			COL_HTREE_MIN_HASH + " VARCHAR(255), " +        // hash tree root hash for config (true,true,true)
			COL_HTREE_PUBONLY_HASH + " VARCHAR(255), " +    // hash tree root hash for config (false,true,false)
			COL_HTREE_MAX_HASH + " VARCHAR(255), " +        // hash tree root hash for config (false,false,false)
			"PRIMARY KEY (" + COL_NAME + ", " + COL_VERSION + ")"
		+ ")";
		stmt.executeUpdate(sql);
		
		// create application stats table
		sql = "CREATE TABLE IF NOT EXISTS " + T_APPLICATION +  "(" +
			COL_ID + " INTEGER, " +
			COL_NAME + " VARCHAR(255) not NULL, " +        // package name
			COL_VERSION + " INTEGER not NULL, " +          // version code
			COL_SHAREDUID + " VARCHAR(255), " +            // shared uid
			COL_PROCESSING_TIME + " INTEGER not NULL, " +  // processing time in ms
			COL_APP_PACKAGES + " INTEGER not NULL, " +     // number of non-empty app packages
			COL_APP_CLASSES + " INTEGER not NULL, " +      // number of app classes
			COL_RELEASEDATE + " INTEGER, " +       		   // long milliseconds since beginning
			"PRIMARY KEY (" + COL_NAME + ", " + COL_VERSION + ")"
		+ ")";
		stmt.executeUpdate(sql);	

		// create profile match table
		sql = "CREATE TABLE IF NOT EXISTS " + T_PROFILE +  "(" +
			COL_ID + " INTEGER PRIMARY KEY AUTOINCREMENT, " +
			COL_LIBID + " INTEGER NOT NULL, " +               // Reference to T_LIBRARY.COL_ID
			COL_APPID + " INTEGER NOT NULL, " +               // Reference to T_APPLICATION.COL_ID
			COL_ISOBFUSCATED + " INTEGER NOT NULL, " +        // boolean, either 0 or 1
			COL_ROOTPCKG_PRESENT  + " INTEGER NOT NULL, " +   // boolean, either 0 or 1
			COL_MATCHLEVEL + " INTEGER NOT NULL, " +          // see SerializableProfileMatch.matchLevel
			COL_SIMSCORE + " REAL, " +                        // similarity score if we have partial matching
			COL_MATCH_CONF_MIN + " INTEGER, " +               // boolean, 0 or 1, if config (true,true,true) matches
			COL_MATCH_CONF_PUBONLY + " INTEGER, " +           // boolean, 0 or 1, if config (false,true,false) matches
			COL_MATCH_CONF_MAX + " INTEGER "                  // boolean, 0 or 1, if config (false,false,false) matches
		+ ")";
		stmt.executeUpdate(sql);
		
		// create naive package name match table
		sql = "CREATE TABLE IF NOT EXISTS " + T_PACKAGE_MATCH +  "(" +
			COL_APPID + " INTEGER NOT NULL, " +                 // Reference to T_APPLICATION.COL_ID
			COL_LIBNAME + " VARCHAR(255) not NULL, " +          // library name
			"PRIMARY KEY (" + COL_APPID + ", " + COL_LIBNAME + ")"
		+ ")";
		stmt.executeUpdate(sql);
				
	}
	
	
	public static void updateDB(Connection con, List<LibProfile> profiles, List<SerializableAppStats> stats) throws SQLException {
		logger.info("Update Database..");

		long starttime = System.currentTimeMillis();

		final PreparedStatement ps_library = con.prepareStatement("INSERT INTO " + T_LIBRARY + " VALUES (?,?,?,?,?,?,?,?,?,?,?,?)");
		final PreparedStatement ps_app = con.prepareStatement("INSERT INTO " + T_APPLICATION + " VALUES (?,?,?,?,?,?,?,?)");
		final PreparedStatement ps_profile = con.prepareStatement("INSERT INTO " + T_PROFILE + " VALUES (?,?,?,?,?,?,?,?,?,?)");
		final PreparedStatement ps_pckgMatch = con.prepareStatement("INSERT INTO " + T_PACKAGE_MATCH + " VALUES (?,?)");
		
		// add all library profiles
		HashMap<Pair<String,String>, Integer> profile2ID = new HashMap<Pair<String,String>, Integer>();
		
		for (int i = 0; i < profiles.size(); i++) {
			LibProfile lib = profiles.get(i);
		
			ps_library.setInt(1, i+1);
			ps_library.setString(2, lib.description.name);
			ps_library.setString(3, lib.description.category.toString());
			ps_library.setString(4, lib.description.version);
			ps_library.setLong(5, lib.description.date == null? 0 : lib.description.date.getTime());
			ps_library.setInt(6, lib.packageTree.getNumberOfNonEmptyPackages());
			ps_library.setInt(7, lib.packageTree.getNumberOfAppClasses());
			
			for (HashTree htree: lib.hashTrees)
				if (htree.hasDefaultConfig())
					ps_library.setInt(8, htree.getNumberOfMethods());
			
			ps_library.setString(9, lib.packageTree.getRootPackage());
			
			HashTree tree = HashTree.getTreeByConfig(lib.hashTrees, true, true, true);
			ps_library.setString(10, tree == null? "" : Hash.hash2Str(tree.getRootHash()));

			tree = HashTree.getTreeByConfig(lib.hashTrees, false, true, false);
			ps_library.setString(11, tree == null? "" : Hash.hash2Str(tree.getRootHash()));
			
			tree = HashTree.getTreeByConfig(lib.hashTrees, false, false, false);
			ps_library.setString(12, tree == null? "" : Hash.hash2Str(tree.getRootHash()));

			ps_library.execute();
			
			profile2ID.put(lib.getLibIdentifier(), i+1);
			logger.info(Utils.INDENT + "- Added library (" + (i+1) + "/" + profiles.size() + "): " + lib.getLibIdentifier());
		}

		
		// update app / profile match table
		for (int i = 0; i < stats.size(); i++) {
			SerializableAppStats appStat = stats.get(i);
			int appId = i+1;
			
			ps_app.setInt(1, appId);
			ps_app.setString(2, appStat.manifest.getPackageName());
			ps_app.setInt(3, appStat.manifest.getVersionCode());
			ps_app.setString(4, appStat.manifest.getSharedUserId().isEmpty()? null : appStat.manifest.getSharedUserId());
			ps_app.setLong(5, appStat.processingTime);
			ps_app.setInt(6, appStat.appPackageCount);
			ps_app.setInt(7, appStat.appClassCount);
			
//			logger.debug(LogConfig.INDENT + "- add app from " + appStat.appFileName + " : " + appStat.manifest.getPackageName() + "  (version: " + appStat.manifest.getVersionCode() + ")");
			ps_app.execute();

			
			/* update profile matches */
			
			// get unique libnames and the max simScore
			Map<String, Float> uniqueLibraries = new HashMap<String,Float>();
			for (SerializableProfileMatch pm: appStat.pMatches) {
				if (!uniqueLibraries.containsKey(pm.libName) || pm.matchLevel == SerializableProfileMatch.MATCH_ALL_CONFIGS || pm.simScore > uniqueLibraries.get(pm.libName))
					uniqueLibraries.put(pm.libName, pm.matchLevel == SerializableProfileMatch.MATCH_ALL_CONFIGS? 1f : pm.simScore);
			}
			
			Set<String> matchedLibs = new HashSet<String>();
			
			for (SerializableProfileMatch pm: appStat.pMatches) {
				if (pm.matchLevel < SerializableProfileMatch.MATCH_ALL_CONFIGS && pm.simScore < uniqueLibraries.get(pm.libName)) continue;  // only export matches with highest sim Score
				matchedLibs.add(pm.libName);
				
				int libId = profile2ID.get(pm.getLibIdentifier());
								
				ps_profile.setInt(2, libId);
				ps_profile.setInt(3, appId);
				ps_profile.setBoolean(4, pm.isLibObfuscated);
				ps_profile.setInt(5, pm.libRootPackagePresent? 1 : 0);
				ps_profile.setInt(6, pm.matchLevel);
				ps_profile.setFloat(7, pm.matchLevel == SerializableProfileMatch.MATCH_ALL_CONFIGS? 1f : pm.simScore);
				
				 // did configs match?
				int[] cfg = new int[]{0, 0, 0};  // TODO deprecated

				ps_profile.setInt(8, cfg[0]);
				ps_profile.setInt(9, cfg[1]);
				ps_profile.setInt(10, cfg[2]);
				
				ps_profile.execute();
			}
			
			// update package name matches
			Set<String> alreadyAdded = new HashSet<String>();
			for (String lib: appStat.packageMatches) {
				   // we currently exclude play services and Guava (com.google), as the auto root package name detection does not work properly
				if (!matchedLibs.contains(lib) && !lib.startsWith("Google Play Services") && !lib.startsWith("Guava") && alreadyAdded.add(lib)) {
					ps_pckgMatch.setInt(1, appId);
					ps_pckgMatch.setString(2, lib);
					ps_pckgMatch.execute();
				}
			}
			
			logger.info(Utils.INDENT + "- Added app (" + appId + "/" + stats.size() + "): " + appStat.manifest.getPackageName() + " (" + appStat.manifest.getVersionCode() + ")");
		}

		logger.info("DB Update (" + profiles.size() + " lib profiles, " + stats.size() + " app stats) done in " + Utils.millisecondsToFormattedTime(System.currentTimeMillis() - starttime));
	}
}
