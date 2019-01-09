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

package de.infsec.tpl.profile;

import java.io.File;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import de.infsec.tpl.hashtree.HashTree;
import de.infsec.tpl.modules.libprofiler.LibraryProfiler;
import org.apache.commons.cli.ParseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ibm.wala.ipa.cha.IClassHierarchy;

import de.infsec.tpl.pkg.PackageTree;
import de.infsec.tpl.utils.Utils;


public abstract class Profile implements Serializable {
	private static final long serialVersionUID = 4112271380387644511L;

	private static final Logger logger = LoggerFactory.getLogger(de.infsec.tpl.profile.Profile.class);
	
	// Package structure of the library|app
	public PackageTree packageTree;
	
	public List<HashTree> hashTrees;

	protected Profile(PackageTree pTree, List<HashTree> hashTrees) {
		this.packageTree = pTree;
		this.hashTrees = hashTrees;
	}
	
	public static PackageTree generatePackageTree(IClassHierarchy cha) {
		logger.info("= PackageTree =");
		PackageTree tree = PackageTree.make(cha, true);
		tree.print(true);
		
		logger.debug("");
		logger.debug("Package names (included classes):");
		Map<String,Integer> pTree = tree.getPackages();
		for (String pkg: pTree.keySet())
			logger.debug(Utils.INDENT + pkg + " (" + pTree.get(pkg) + ")");

		logger.info("");
		
		return tree;
	}
		
	
	public static List<HashTree> generateHashTrees(final IClassHierarchy cha) {
		HashTree ht = new HashTree();
		ht.generate(cha);
		return Collections.singletonList(ht);
	}


	public static List<LibProfile> loadLibraryProfiles(File profilesDir) throws ParseException {
		long s = System.currentTimeMillis();
		List<LibProfile> profiles = new ArrayList<LibProfile>();
		logger.info("Load library profiles:");

		try {
			// de-serialize library profiles
			for (File f : Utils.collectFiles(profilesDir, new String[]{LibraryProfiler.FILE_EXT_LIB_PROFILE})) {
				LibProfile lp = (LibProfile) Utils.disk2Object(f);
				profiles.add(lp);
			}

			profiles.sort(LibProfile.comp);
			logger.info(Utils.indent() + "Loaded " + profiles.size() + " profiles in " + Utils.millisecondsToFormattedTime(System.currentTimeMillis() - s));
			logger.info("");
		} catch (ClassNotFoundException e) {
			throw new ParseException("Could not load profiles: " + Utils.stacktrace2Str(e));
		}

		if (profiles.isEmpty()) {
			throw new ParseException("No profiles found in " + profilesDir + ". Check your settings!");
		}

		return profiles;
	}

}
