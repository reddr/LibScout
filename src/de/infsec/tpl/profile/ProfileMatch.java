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

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

import de.infsec.tpl.config.LibScoutConfig;
import de.infsec.tpl.stats.Exportable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.infsec.tpl.hash.HashTree;
import de.infsec.tpl.hash.HashTree.ClassNode;
import de.infsec.tpl.hash.HashTree.Config;
import de.infsec.tpl.hash.HashTree.MethodNode;
import de.infsec.tpl.hash.HashTree.Node;
import de.infsec.tpl.hash.HashTree.PackageNode;
import de.infsec.tpl.pkg.PackageTree;
import de.infsec.tpl.utils.Utils;
import de.infsec.tpl.utils.Utils.IPredicate;



public class ProfileMatch implements Exportable, Serializable {
	private static final long serialVersionUID = 62089083096037815L;
	private static final Logger logger = LoggerFactory.getLogger(de.infsec.tpl.profile.ProfileMatch.class);

	public static final float MIN_PARTIAL_MATCHING_SCORE = .7f;
	public static final float MIN_PCKG_SCORE = .3f; 
	public static final float MIN_CLAZZ_SCORE = .33f;
	public static final float MIN_CLAZZ_APP_SCORE = .2f;

	public static enum MatchLevel {PACKAGE, CLASS, METHOD};

	public LibProfile lib;

	// if lib code usage analysis is enabled, store normalized (i.e. if matched root packages differs from original root package) lib method signatures used
	public Set<String> usedLibMethods = new TreeSet<String>();
	
	private PackageTree matchedPackageTree;
	public boolean libRootPackagePresent;
		
	// special sim scores
	public static final float MATCH_HTREE_FULL = 1f;
	public static final float MATCH_HTREE_NONE = 0f;
	public static final float MATCH_HTREE_NO_ROOT_PCKG = -1f;
	
	// stores the results for each HashTree comparison
	private List<HTreeMatch> results;
	
	public class HTreeMatch {
		public Config config;  // HashTree identifier - config        

		public List<PackageNode> matchingNodes;   // list of package nodes that matched (partially)
		public Float simScore = MATCH_HTREE_NONE;  // between 0f..1f for partial match 
		
		// if we have a partial match, we need the partition
		public String rootPackage;
 
		
		public HTreeMatch(Config config) {
			this.config = config;
		}
		
		public boolean isFullMatch() {
			return simScore == MATCH_HTREE_FULL;
		}

		public boolean isPartialMatch() {
			return simScore > MATCH_HTREE_NONE && simScore < MATCH_HTREE_FULL;
		}

		@Override
		public String toString() {
			StringBuilder sb = new StringBuilder();
			sb.append("Config: " + config + "\n");
			if (isFullMatch())
				sb.append("  - full match");
			else if (isPartialMatch())
				sb.append("  - partial match: root package: " + rootPackage + "  simScore: " + simScore);
			else if (simScore == MATCH_HTREE_NONE)
				sb.append("  - no match -");
			return sb.toString();
		}
	}
	
	public class Export {
		public final String libName;
		public final String libVersion;
		public final boolean isOriginalPackageName;
		public final String  libRootPackage;
		public final boolean includesSecurityVulnerability;
		public final boolean includesSecurityVulnerabilityFix;
		public float simScore = 0f;  // 1f if exact match
		public final String comment;

		// if lib code usage analysis is enabled, store normalized (i.e. if matched root packages differs from original root package) lib method signatures used
		public Set<String> usedLibMethods = new TreeSet<String>();

		public Export(ProfileMatch pm) {
			this.libName = pm.lib.description.name;
			this.libVersion = pm.lib.description.version;
			this.isOriginalPackageName = !pm.isLibObfuscated();
			this.libRootPackage = pm.getMatchedPackageTree().getRootPackage() != null? getMatchedPackageTree().getRootPackage() : "";
			this.includesSecurityVulnerability = pm.lib.description.comment.contains("[SECURITY]");
			this.includesSecurityVulnerabilityFix = pm.lib.description.comment.contains("[SECURITY-FIX]");
			this.simScore = pm.getHighestSimScore().simScore;
			this.comment = LibScoutConfig.Reporting.showComments? pm.lib.description.comment : "";

			if (!pm.usedLibMethods.isEmpty())
				this.usedLibMethods = pm.usedLibMethods;
		}
	}

	@Override
	public Export export() {
		return new Export(this);
	}

	public void addResult(HTreeMatch res) {
		results.add(res);
		Collections.sort(results, SIM_SCORE_COMPARATOR);  // ensure that results are sorted
	}
	
	public HTreeMatch getResultByConfig(Config cfg) {
		for (HTreeMatch htm: results)
			if (htm.config.equals(cfg))
				return htm;
		return null;
	}
	

	public List<HTreeMatch> getBestResults(int topX) {
		int upperLimit = Math.min(topX, results.size());
		return results.subList(0, upperLimit);
	}
	
	public void printResults(int topX) {
		logger.info("Profile results:");
		Collections.sort(results, new SimScoreComparator());
		for (int i = 0; i < Math.min(topX, results.size()); i++) {
			if (results.get(i).simScore > MATCH_HTREE_NONE)
				logger.info("- " + results.get(i));
		}
	}
	
	
	public HTreeMatch createResult(Config config) {
		return new HTreeMatch(config);
	}
	
	public ProfileMatch(LibProfile lib) {
		this.results = new ArrayList<HTreeMatch>();
		this.lib = lib;
	}
	

	public void print() {
		final String VULN_INDICATOR = "[SECURITY]";   // indicates that this version includes a security vulnerability
		final String VULN_FIX_INDICATOR = "[SECURITY-FIX]";   // indicates that this version includes a fix for a security vulnerability

 		for (String str: lib.description.getDescription()) {
			if (str.contains("comment:") &&
			   (!LibScoutConfig.Reporting.showComments && !(str.contains(VULN_INDICATOR) || str.contains(VULN_FIX_INDICATOR)))) continue;

			if (str.contains("version") && lib.isDeprecatedLib())
				str += "  [OLD VERSION]";    // TODO store in db?
			
			logger.info(Utils.INDENT + str);
		}
		
		logger.info(Utils.INDENT + "lib root package: \"" + lib.packageTree.getRootPackage() + "\"" + (isLibObfuscated()? "  (in app: \"" + getMatchedPackageTree().getRootPackage() + "\")" : ""));
		
		if (logger.isDebugEnabled() && !usedLibMethods.isEmpty()) {
			logger.debug("");
			logger.debug(Utils.INDENT + "- used library methods in app -");
			for (String sig: usedLibMethods) {
				logger.debug(Utils.INDENT2 + "- method: " + sig);
			}
			logger.debug("");
		}
		
		if (logger.isTraceEnabled())
			getMatchedPackageTree().print(false);
		logger.info("");
	}

	
	public boolean doAllConfigsMatch() {   // TODO to be deprecated
		for (HTreeMatch htm: results) {
			if (!htm.isFullMatch()) 
				return false;
		}
		return true;
	}
	
	
	public boolean isMatch() {
		for (HTreeMatch htm: results) {
			if (htm.isFullMatch())  // at least one exact match 
				return true;
		}
		return false;
	}

	public boolean isPartialMatch() {
		if (isMatch())
			return false;
		
		for (HTreeMatch htm: results) {
			if (htm.isPartialMatch())  // at least one partial match 
				return true;
		}
		return false;
	}

	

	public List<Config> getMatchedConfigs() {
		ArrayList<Config> result = new ArrayList<Config>();
		for (HTreeMatch htm: results) {
			if (htm.isFullMatch())
				result.add(htm.config);
		}
		
		return result;
	}

	public List<Config> getPartiallyMatchedConfigs() {
		ArrayList<Config> result = new ArrayList<Config>();
		for (HTreeMatch htm: results) {
			if (htm.isPartialMatch())
				result.add(htm.config);
		}
		
		return result;
	}

	
	
	public HTreeMatch getHighestSimScore() {
		return results.isEmpty()? null : results.get(0);
	}
	
	
	
	public PackageTree getMatchedPackageTree() {
		if (isMatch()) {
			if (matchedPackageTree == null) {
				for (HTreeMatch htm: results) {
					if (htm.isFullMatch()) {
						matchedPackageTree = PackageTree.make(htm.matchingNodes);
						break;
					}
				}
			}
			
			return matchedPackageTree;
		}
		
		return null;
	}
	

	/**
	 * Does a certain HashTree config match (this requires a full match!)
	 * @param filterDups
	 * @param filterInnerClasses
	 * @param accessFlagFilter
	 * @return
	 */
	public boolean matchesConfig(final boolean filterDups, final boolean filterInnerClasses, final int accessFlagFilter) {
		for (HTreeMatch htm: results) {
			if (htm.isFullMatch()) {
				if (htm.config.filterDups == filterDups && htm.config.filterInnerClasses == filterInnerClasses && htm.config.accessFlagsFilter == accessFlagFilter)
					return true;
			}
		}
		
		return false;
	}
	
	
	/**
	 * Compares the matched app package node identifier with the library package node identifier
	 * If both (sorted) lists match, the library is not (re-)obfuscated
	 * @return  false, if lib only matches partially or all package names match, true otherwise
	 */
	public boolean isLibObfuscated() {
		for (HTreeMatch htm: results) {
			if (htm.isFullMatch()) {  // take first exact match 
				HashTree libHTree = HashTree.getTreeByConfig(lib.hashTrees, htm.config);
				
				// cast list objects from Node to PackageNode
				ArrayList<PackageNode> libNodes = new ArrayList<PackageNode>();
				for (Node n: libHTree.getPackageNodes())
					libNodes.add((PackageNode) n);
				
				return !comparePackageNodes(libNodes, htm.matchingNodes);
			}
		}
		
		return false;
	}
	

	public static boolean comparePackageNodes(List<PackageNode> c1, List<PackageNode> c2) {
		Comparator<PackageNode> pckgComp = new Comparator<PackageNode>() {

			@Override
			public int compare(PackageNode pn1, PackageNode pn2) {
				return pn1.packageName.compareTo(pn2.packageName);
			}
		};

		Collections.sort(c1, pckgComp);
		Collections.sort(c2, pckgComp);
	
		int max = Math.min(c1.size(), c2.size());
		for (int i = 0; i < max; i++) {
			if (!c1.get(i).packageName.equals(c2.get(i).packageName))
				return false;
		}

		return true;
	}
	

	
	/**
 	 * Generates a {@link Node} filter
 	 */
 	public static final IPredicate<Node> getNodeFilter(final MatchLevel lvl) {
 		return new IPredicate<Node>() {
 			@Override
 			public boolean apply(Node node) {
 				switch (lvl) {
					case CLASS:
						return node instanceof ClassNode;
					case METHOD:
						return node instanceof MethodNode;
					case PACKAGE:
						return node instanceof PackageNode;
 				}
 				return false;
 			}
 		};
 	}
 
	
	private class SimScoreComparator implements Comparator<HTreeMatch> {
		@Override
		public int compare(HTreeMatch m1, HTreeMatch m2) {
			return Float.compare(m2.isFullMatch()? 1f : m2.simScore, m1.isFullMatch()? 1f : m1.simScore);   // sort descending
		}
	}
	
	public final SimScoreComparator SIM_SCORE_COMPARATOR = new SimScoreComparator();
 
}
