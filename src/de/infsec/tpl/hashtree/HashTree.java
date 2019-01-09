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

package de.infsec.tpl.hashtree;


import com.google.common.hash.HashFunction;
import com.google.common.hash.Hasher;
import com.google.common.hash.Hashing;
import com.ibm.wala.classLoader.IClass;
import com.ibm.wala.classLoader.IMethod;
import com.ibm.wala.ipa.cha.IClassHierarchy;
import de.infsec.tpl.hash.AccessFlags;
import de.infsec.tpl.hashtree.comp.clazz.DefaultClassNodeComp;
import de.infsec.tpl.hashtree.comp.clazz.IClassNodeComp;
import de.infsec.tpl.hashtree.comp.method.IMethodNodeComp;
import de.infsec.tpl.hashtree.comp.method.SignatureMethodNodeComp;
import de.infsec.tpl.hashtree.comp.pckg.DefaultPackageNodeComp;
import de.infsec.tpl.hashtree.comp.pckg.IPackageNodeComp;
import de.infsec.tpl.hashtree.node.*;
import de.infsec.tpl.pkg.PackageUtils;
import de.infsec.tpl.utils.Utils;
import de.infsec.tpl.utils.WalaUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Serializable;
import java.util.*;
import java.util.stream.Collectors;

/*
 * props:
 *    single/multi-version
 *
 * common functionality::
 *   - stats
 *   - debug?
 *   - generate?? depends on data
  *
 * abstract/interface Node
 *   props::  single vs multi-version nodes
 *
 */


/**
 * A Merkle hash tree implementation used to efficiently
 * identify code reuse in apps through library code
 */
public class HashTree implements Serializable {
	private static final long serialVersionUID = 8890771073564531337L;

	transient private static final Logger logger = LoggerFactory.getLogger(HashTree.class);

	transient final IPackageNodeComp pnComp;
	transient final IClassNodeComp cnComp;
	transient final IMethodNodeComp mnComp;

	private Node rootNode;

	protected Config config = new Config();

	public static class Config implements Serializable {
		private static final long serialVersionUID = 1190771073564531337L;

		public static HashFunction hf = Hashing.md5();
		public static AccessFlags accessFlagsFilter = AccessFlags.NO_FLAG;

		// verboseness
		public static boolean keepPackageNames = true;
		public static boolean keepClassNames = false;
		public static boolean keepMethodSignatures = false;

		// node pruning
		public static boolean pruneClasses = false;
		public static boolean pruneMethods = true;
	}


	public HashTree() {
		this(new DefaultPackageNodeComp(), new DefaultClassNodeComp(), new SignatureMethodNodeComp());
	}

	public HashTree(IPackageNodeComp pnComp, IClassNodeComp cnComp, IMethodNodeComp mnComp) {
		this.pnComp = pnComp;
		this.cnComp = cnComp;
		this.mnComp = mnComp;
	}

	@Override
	public boolean equals(Object obj) {
		if (!(obj instanceof HashTree))
			return false;

		return Arrays.equals(this.getRootHash(), ((HashTree) obj).getRootHash());
	}


	public static Node compNode(Collection<? extends Node> nodes, boolean prune) {
		Hasher hasher = getHasher();
		nodes.stream().sorted(HashUtils.comp).forEach(n -> hasher.putBytes(n.hash));

		Node n = new Node(hasher.hash().asBytes());
		if (!prune)
			n.childs.addAll(nodes);
		return n;
	}

	public void generate(IClassHierarchy cha) {
		generate(cha, Short.MIN_VALUE);
	}

	protected void generate(IClassHierarchy cha, Short nodeId) {
		logger.debug("Generate hash tree..");

		int classHashCount = 0;
		int methodHashCount = 0;

		// create map package name -> set of clazzNodes
		HashMap<String, List<ClassNode>> packageMap = new HashMap<>();

		for (IClass clazz: cha) {
			if (WalaUtils.isAppClass(clazz)) {

				Collection<IMethod> methods = clazz.getDeclaredMethods();

				// filter methods by access flag
				if (Config.accessFlagsFilter != AccessFlags.NO_FLAG) {
					methods = methods.stream()
						.filter(m -> { int code = AccessFlags.getMethodAccessCode(m);  return code > 0 && (code & Config.accessFlagsFilter.getValue()) == 0x0; })  // if predicate is true, keep in list
						.collect(Collectors.toCollection(ArrayList::new));
				}

				List<MethodNode> methodNodes = methods.stream()
					 .filter(m -> !(m.isBridge() || m.isMethodSynthetic()))  // normalize java|dex bytecode by skipping compiler-generated methods
					 .map(m -> mnComp.comp(m, true /* TODO to be changed */))
					 .sorted(HashUtils.comp)  // sort but do not filter dups
					 .collect(Collectors.toList());

				// normalize - skip classes with no methods
				if (methodNodes.isEmpty()) {
					logger.trace(Utils.INDENT + ">> No methods found for clazz: " + WalaUtils.simpleName(clazz));
					continue;
				}

				// update stats
				methodHashCount += methodNodes.size();
				classHashCount++;

				ClassNode clazzNode = cnComp.comp(methodNodes, clazz, Config.pruneMethods);

				// annotate class and method nodes
				if (nodeId > 0)
					annotate(clazzNode, nodeId, true);

				// keep track on classes per package
				String pckgName = PackageUtils.getPackageName(clazz);
				if (!packageMap.containsKey(pckgName)) {
					packageMap.put(pckgName, new ArrayList<>());
				}
				packageMap.get(pckgName).add(clazzNode);
			}
		}

		packageMap.values().forEach(l -> l.sort(HashUtils.comp));  // sort class nodes
		List<PackageNode> packageNodes = packageMap.keySet().stream()
			.map(p -> pnComp.comp(packageMap.get(p), p, cha, Config.pruneClasses))
			.sorted(HashUtils.comp)
			.collect(Collectors.toList());

		// generate root
		rootNode = compNode(packageNodes, false);

		// annotate root and package nodes
		if (nodeId > 0) {
			packageNodes.forEach(pn -> annotate(pn, nodeId, false));
			annotate(rootNode, nodeId, false);
		}

		logger.debug(Utils.INDENT + "- generated " + packageNodes.size() + " package hashes.");
		logger.debug(Utils.INDENT + "- generated " + classHashCount    + " clazz hashes.");
		logger.debug(Utils.INDENT + "- generated " + methodHashCount   + " method hashes.");
		logger.debug(Utils.INDENT + "=> Library Hash: " + HashUtils.hash2Str(rootNode.hash));
	}


	private void annotate(Node n, Short id, boolean inclChilds) {
		n.versions.add(id);

		if (inclChilds)
			n.childs.forEach(c -> c.versions.add(id));
	}


	/*
	 * Getter methods
	 */
	public Node getRootNode() {
		return this.rootNode;
	}

	public byte[] getRootHash() {
		return this.rootNode.hash;
	}

	public Config getConfig() {
		return this.config;
	}

	public static Hasher getHasher() {
		return Config.hf.newHasher();
	}



	public static List<PackageNode> toPackageNode(Collection<Node> col) {
		return col.stream()
			.filter(n -> n instanceof PackageNode)
			.map(n -> (PackageNode) n).collect(Collectors.toList());
	}

	public Collection<PackageNode> getPackageNodes() {
		return this.getRootNode().childs.stream().map(pn -> (PackageNode) pn).collect(Collectors.toList());
	}
	
	public int getNumberOfPackages() {
		return rootNode.numberOfChilds();
	}
	
	public int getNumberOfClasses() {
		return rootNode.childs.stream().mapToInt(pn -> pn.childs.size()).sum();
	}
	
	public int getNumberOfClasses(PackageNode pn) {
		return pn.numberOfChilds();
	}
	
	public int getNumberOfMethods(PackageNode pn) {
		return pn.childs.stream().mapToInt(cn -> cn.childs.size()).sum();
	}

	public int getNumberOfMethods() {
		return rootNode.childs.stream()
			.map(pn -> pn.childs)
			.flatMap(Collection::stream)
			.mapToInt(cn -> cn.childs.size()).sum();
	}
}
