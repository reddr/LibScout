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

package de.infsec.tpl.profile;

import java.io.Serializable;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ibm.wala.ipa.cha.IClassHierarchy;

import de.infsec.tpl.hash.HashTree;
import de.infsec.tpl.hash.HashTree.HashAlgorithm;
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
		
	
	/**
	 * Generate hash trees for a certain {@link PackageTree} for all configurations
	 * @param cha  the {@link IClassHierarchy} instance
	 * @return  a List of {@link HashTree} for every configuration
	 */
	
// TODO: option to set different modes (normal, trace+pubonly, normal+pubonly)	
	public static List<HashTree> generateHashTrees(final IClassHierarchy cha) {
		final HashAlgorithm algorithm = HashAlgorithm.MD5;
		
		List<HashTree> hTrees = new ArrayList<HashTree>();
		try {
			boolean filterDups = false;
			boolean filterInnerClasses = false;
			
			HashTree hashTree = new HashTree(filterDups, filterInnerClasses, algorithm);
//			hashTree.setPublicOnlyFilter();  // TODO
			hashTree.generate(cha);
			hTrees.add(hashTree);
		} catch (NoSuchAlgorithmException e) {
			logger.error(Utils.stacktrace2Str(e));
		}	
		
		return hTrees;
	}
}
