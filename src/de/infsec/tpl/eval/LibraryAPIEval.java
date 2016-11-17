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

package de.infsec.tpl.eval;

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

import de.infsec.tpl.hash.Hash;
import de.infsec.tpl.hash.HashTree;
import de.infsec.tpl.profile.LibProfile;
import de.infsec.tpl.utils.Utils;

/**
 * Check how different library versions differ in their public API
 * @author ederr
 *
 */
public class LibraryAPIEval {
	private static final Logger logger = LoggerFactory.getLogger(de.infsec.tpl.eval.LibraryAPIEval.class);
	private static List<LibProfile> profiles; 
	private static Map<String, List<String>> report;
	
	public void doEval(List<LibProfile> libProfiles) {
		profiles = libProfiles;
		TreeSet<String> uniqueLibraries = new TreeSet<String>(LibProfile.getUniqueLibraries(profiles).keySet());

		logger.info("= Evaluate libraries =");
		logger.info(Utils.INDENT + "Loaded " + profiles.size() + " library profiles for " + uniqueLibraries.size() + " distinct libraries");
/*
		List<LibCodeOnlyResult> res = new ArrayList<LibCodeOnlyResult>();
		logger.info("- Check for code only changes -");
		for (String lib: uniqueLibraries)
			res.add(checkForCodeOnlyChanges(lib, true));
		reportResults(res);
		logger.info("");

		logger.info("- Check for code only changes -");
		res = new ArrayList<LibCodeOnlyResult>();
		for (String lib: uniqueLibraries)
			res.add(checkForCodeOnlyChanges(lib, false));
		reportResults(res);
		logger.info("");
		logger.info("");

	*/	
		logger.info("- Evaluate public library API (Requires profiles with full DEBUG info) -");
		report = new HashMap<String, List<String>>();
		for (String lib: uniqueLibraries) {
			checkPublicAPI(lib, true);
		}
		
		logger.info("");
		logger.info("= Report =");
		for (String category: report.keySet()) {
			logger.info("## Category: " + category + " ##");
			for (String line: report.get(category))
				logger.info(line);
		}
	}
	
	private void reportResults(List<LibCodeOnlyResult> list) {
		if (list.isEmpty()) return;
		
		boolean includeBetas = list.get(0).includeBetaVersions;
		int total = 0;
		int dups = 0;
		Map<Integer,Integer> numberOfDupsMap = new HashMap<Integer,Integer>();
		
		int dupFreeLibs = 0;
		for (LibCodeOnlyResult l: list) {
			dupFreeLibs += l.libHasNoDups? 1 : 0;
			total += l.numberOfLibVersions;
			for (Set<String> e: l.results) {
				dups += e.size();
				if (!numberOfDupsMap.containsKey(e.size()))
					numberOfDupsMap.put(e.size(), 0);
				numberOfDupsMap.put(e.size(), numberOfDupsMap.get(e.size())+1);
			}
		}
				
		logger.info("## ---------------------------------------------------------------------------------- ##");
		logger.info("= Number of libs without dups: " + dupFreeLibs);
		logger.info("= Resulting percentage of code-only changes (" + (includeBetas? "incl." : "excl.") + " betas): "
				+ dups + "/" + total + " ("	+ Utils.computePercentage(dups, total) + "%) ==");
		
		int numberOfDups = 0;
		int x = 0;
		for (Integer i: numberOfDupsMap.keySet()) {
			logger.info(Utils.INDENT + "# of " + i + " dups: " + numberOfDupsMap.get(i));
			numberOfDups += (i * numberOfDupsMap.get(i));
			
			if (i != 0)
				x += numberOfDupsMap.get(i);
		}
		
		logger.info(Utils.INDENT + "average dups: " + numberOfDups + "/" + x + "  (" + ((float) numberOfDups / (float) x) + ")");
		logger.info("## ---------------------------------------------------------------------------------- ##");
	}
	
	
	
	private class LibCodeOnlyResult {
		public String name;
		public String category;
		public boolean includeBetaVersions;
		public boolean libHasNoDups;
		public int numberOfLibVersions;
		public List<Set<String>> results;
		
		public LibCodeOnlyResult(String name, String category, boolean beta, boolean libHasNoDups, int versions, List<Set<String>> results) {
			this.name = name;
			this.category = category;
			this.includeBetaVersions = beta;
			this.libHasNoDups = libHasNoDups;
			this.numberOfLibVersions = versions;
			this.results = results;
		}
	}

	
	private LibCodeOnlyResult checkForCodeOnlyChanges(String lib, boolean includeBetaVersions) {
		List<LibProfile> list = new ArrayList<LibProfile>();
		for (LibProfile lp: profiles) {
			if (lp.description.name.equals(lib)) {
				list.add(lp);
			}
		}
		logger.info(Utils.INDENT + "- Check lib: " + list.get(0).description.name + " [" + list.get(0).description.category + "] -");
	
		List<Set<String>> eq = new ArrayList<Set<String>>();
		eq.add(new TreeSet<String>());
		
		for (int i = 0; i < list.size(); i++) {
			for (int k = i+1; k < list.size(); k++) {
				LibProfile lp0 = list.get(i);
				LibProfile lp1 = list.get(k);
				
				if (!includeBetaVersions) {
					if (lp0.description.version.contains("rc") || lp0.description.version.contains("RC") || lp0.description.version.contains("beta")) continue;
					if (lp1.description.version.contains("rc") || lp1.description.version.contains("RC") || lp1.description.version.contains("beta")) continue;
				}
				
				boolean allHashTreeMatches = true;
				
				differ:
				for (boolean filterDups: new boolean[]{false}){ //true,false}) {
					for (boolean publicOnly: new boolean[]{false}){ //true,false}) {
						for (boolean filterInnerClasses: new boolean[]{false}){ //true,false}) {
							HashTree ht0 = HashTree.getTreeByConfig(lp0.hashTrees, filterDups, publicOnly, filterInnerClasses);
							HashTree ht1 = HashTree.getTreeByConfig(lp1.hashTrees, filterDups, publicOnly, filterInnerClasses);
							allHashTreeMatches = ht0.equals(ht1);
							if (!allHashTreeMatches) {
								if (!eq.get(eq.size()-1).isEmpty())
									eq.add(new TreeSet<String>());
								break differ;
							}
						}
					}
				}

				
				
				if (allHashTreeMatches) {
					boolean alreadyAdded = false;
					for (Set<String> e: eq) {
						if (e.contains(lp0.description.version)) {
							e.add(lp1.description.version);
							alreadyAdded = true;
							break;
						}
					}
					if (!alreadyAdded) {
						eq.get(eq.size()-1).add(lp0.description.version);
						eq.get(eq.size()-1).add(lp1.description.version);
					}
				}
			}
		}
		
		int sameVersions = 0;
		for (Set<String> e: eq) {
			if (!e.isEmpty()) {
				logger.info(Utils.INDENT2 + "  - same HashTrees(" + e.size() + ") for versions " + e);
				sameVersions += e.size();
			}
		}
		
		logger.info(Utils.INDENT + "=> code only changes in " + sameVersions + "/" + list.size());
		logger.info("");
		
		return new LibCodeOnlyResult(list.get(0).description.name, list.get(0).description.category.toString(), includeBetaVersions, sameVersions == 0, list.size(), eq);
	}
	
	
	private void checkPublicAPI(String lib, boolean skipBeta) {
		//logger.info(LogConfig.INDENT + "- check lib: " + lib);
		
		List<LibProfile> list = new ArrayList<LibProfile>();
		for (LibProfile lp: profiles) {
			if (lp.description.name.equals(lib)) {
				// if there is at least one version without release-date skip this library
				if (lp.description.date == null)
					return;
				else {
					if (!lp.description.version.matches(".*[a-zA-Z]+.*") || !skipBeta)  // skip alpha/beta/rc ..
						list.add(lp);
				}
			}
		}
		
		// evaluate only if we have at least ten different versions of one lib
		if (list.size() <= 10)
			return;
		
		// sort profiles by release date
		Collections.sort(list, new Comparator<LibProfile>() {
			@Override
			public int compare(LibProfile p0, LibProfile p1) {
				return p0.description.date.compareTo(p1.description.date);
			}
		});

		String cat = list.get(0).description.category.toString();
		if (!report.containsKey(cat))
			report.put(cat, new ArrayList<String>());
		
		logger.info("Name,  Version,  Release-Date, pubApi.size(),  API diff,  API compatible?,  PubOnly Hash equal?");
		float avgDiff = 0f;
		int apiCompatibleCount = 0;
		int hashEqualCount = 0;
		for (int i = 0; i < list.size(); i++) {
			LibProfile lp1 = list.get(i);
			HashTree pubTree1 = HashTree.getTreeByConfig(lp1.hashTrees, false, true, false);
			List<String> pubAPI1 = pubTree1.getAllMethodSignatures();
			
			
			if (i == 0) {
				logger.info(String.format("%s, %7s, %12s, %5d", lp1.description.name, lp1.description.version, lp1.description.getFormattedDate(), pubAPI1.size()));
			} else {
				LibProfile lp0 = list.get(i-1);
				HashTree pubTree0 = HashTree.getTreeByConfig(lp0.hashTrees, false, true, false);
				List<String> pubAPI0 = pubTree0.getAllMethodSignatures();
				
				int apiDiff = pubAPI1.size() - pubAPI0.size();
				avgDiff += apiDiff;
				
				boolean apiCompatible = pubAPI1.containsAll(pubAPI0);
				apiCompatibleCount += apiCompatible? 1 : 0;
				
				boolean hashEqual = Hash.equals(pubTree0.getRootHash(), pubTree1.getRootHash());
				hashEqualCount += hashEqual? 1 : 0;
				logger.info(String.format("%s, %7s, %12s, %5d, %5d, %-5b, %-5b", lp1.description.name, lp1.description.version, lp1.description.getFormattedDate(), pubAPI1.size(), apiDiff, apiCompatible, hashEqual));
			}
		}
		logger.info("  ==>  average API diff: " + (avgDiff / (float) list.size()) + "  api compatible: " + apiCompatibleCount + "/" + list.size() + " (" + Utils.computePercentage(apiCompatibleCount, list.size())  + "%)  Hash equals: " + hashEqualCount + "/" + list.size() + " (" + Utils.computePercentage(hashEqualCount, list.size()) + "%)");
		logger.info("");
		
		report.get(cat).add(Utils.INDENT + "# " + list.get(0).description.name + " (" + list.get(0).description.category + ")");
		report.get(cat).add(Utils.INDENT2 + "- average API diff: " + (avgDiff / (float) list.size()) + "  api compatible: " + apiCompatibleCount + "/" + list.size() + " (" + Utils.computePercentage(apiCompatibleCount, list.size())  + "%)  Hash equals: " + hashEqualCount + "/" + list.size() + " (" + Utils.computePercentage(hashEqualCount, list.size()) + "%)");
	}
	
}
