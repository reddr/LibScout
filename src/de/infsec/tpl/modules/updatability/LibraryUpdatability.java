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


package de.infsec.tpl.modules.updatability;

import java.io.*;
import java.util.*;

import com.google.gson.Gson;
import com.google.gson.stream.JsonReader;
import de.infsec.tpl.modules.libapi.LibApiStats;
import de.infsec.tpl.profile.ProfileMatch;
import de.infsec.tpl.stats.AppStats;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import de.infsec.tpl.utils.Utils;
import de.infsec.tpl.utils.VersionWrapper;


public class LibraryUpdatability {
	private static final Logger logger = LoggerFactory.getLogger(de.infsec.tpl.modules.updatability.LibraryUpdatability.class);

	// libName -> stats
	private Map<String, LibApiStats.Export> lib2ApiStats = new HashMap<>();

	private final int FLAG_UP2DATE = 0;                  // already up2date
	private final int FLAG_NO_UPDATE = -1;               // no update possible without code changes
	private final int FLAG_NO_LIBSTATS_AVAILABLE = -2;   // no libstats available
	private final int FLAG_NO_USED_METHDOS = -3;         // no library methods in use
	

	/**
     *  TODO::
	 *  [OK] check updatability
	 *    	- include nested deps?
	 *   - integrate into libIdentifier
	 *    	- write out stats / extend appstats
   	 *   	- check for sec vuln (+ vuln data should be read from file rather than hardcoded?)
	 */

	public LibraryUpdatability(File fdir) {
		// load lib-api compat information
		loadLibApiCompatData(fdir);
	}

	public void checkUpdatability(AppStats appStats) {
		logger.info("");
		logger.info("== Check library updatability ==");

		// check for every detected lib if we have compat info
		for (ProfileMatch pm: appStats.pMatches) {
			if (pm.isMatch()) {
				// compare with usage info in appstats to infer latest version
				checkLibUpdatability(pm);
			}
		}
	}


	private void loadLibApiCompatData(File fdir) {
		logger.trace("Load lib api compat data:");
		Gson gson = new Gson();

		for (File f : Utils.collectFiles(fdir, new String[]{"json"})) {
			try {
				JsonReader reader = new JsonReader(new FileReader(f));
				LibApiStats.Export libStats = gson.fromJson(reader, LibApiStats.Export.class);

				lib2ApiStats.put(libStats.libName, libStats);
				logger.trace(Utils.indent() + "# lib: " + libStats.libName + "   # versions: " + libStats.apiDiffs.size());
			} catch (Exception e) {
				logger.warn(Utils.stacktrace2Str(e));
			}
		}
	}


	private int checkLibUpdatability(ProfileMatch pm) {
		logger.info("Check: " + pm.lib.getLibIdentifier());
		String libName = pm.lib.description.name;
		String libVersion = pm.lib.description.version;

		// do we have compat info
		if (!lib2ApiStats.containsKey(libName)) {
			logger.info(Utils.indent() + ">> No lib api compat info for library: " + libName);
			return FLAG_NO_LIBSTATS_AVAILABLE;
		}

		LibApiStats.Export libstat = lib2ApiStats.get(libName);

		// check if already latest version
		if (libVersion.equals(libstat.versions.get(libstat.versions.size()-1))) {
			logger.info(Utils.indent() + ">> Library version is already up2date!");
			return FLAG_UP2DATE;
		}

		// check if we have used lib methods
		if (pm.usedLibMethods.isEmpty()) {
			logger.info(Utils.indent() + ">> No identified used library methods!");
			return FLAG_NO_USED_METHDOS;
		}

		// for every API determine max version, then take min version supported by all apis
		TreeSet<String> maxVersions = new TreeSet<>();

		for (String used: pm.usedLibMethods) {
			if (libstat.api2Versions.containsKey(used)) {
				// get max supported version for api (exclude matched version)
				String maxVersion = libstat.api2Versions.get(used).get(libstat.api2Versions.get(used).size()-1);
				logger.debug(Utils.indent() + "API: " + used + "   maxVersion: " + maxVersion);

				if (!maxVersion.equals(libVersion))
					maxVersions.add(maxVersion);
			} else
				logger.debug(Utils.indent() + "Could not lookup API: " + used + "  [protected]");
		}

		if (maxVersions.isEmpty()) {
			logger.info(Utils.indent() + ">> Library is not updatable");
			return FLAG_NO_UPDATE;
		}

		// check if global minVersion is supported by all used apis (= updatable)
		for (String used: pm.usedLibMethods) {
			if (libstat.api2Versions.containsKey(used) && !libstat.api2Versions.get(used).contains(maxVersions.first())) {
				logger.info(Utils.indent() + ">> API: " + used + " does not support min version " + maxVersions.first() + ". Library is not updatable.");
				return FLAG_NO_UPDATE;
			}
		}

		// updatable by how many versions
		int vdiff = libstat.versions.indexOf(maxVersions.first()) - libstat.versions.indexOf(VersionWrapper.valueOf(libVersion).toString());
		logger.info(Utils.indent() + ">> Library is updatable by " + vdiff + " versions (" + maxVersions.first() + ")");
		return vdiff;
	}
}

