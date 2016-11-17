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

package de.infsec.tpl.hash;


import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.Serializable;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.TreeSet;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ibm.wala.classLoader.IClass;
import com.ibm.wala.classLoader.IMethod;
import com.ibm.wala.ipa.cha.IClassHierarchy;
import com.ibm.wala.types.ClassLoaderReference;
import com.ibm.wala.types.Descriptor;

import de.infsec.tpl.IFilter;
import de.infsec.tpl.hash.Hash.ByteArrayComparator;
import de.infsec.tpl.pkg.PackageTree;
import de.infsec.tpl.pkg.PackageUtils;
import de.infsec.tpl.profile.ProfileMatch.MatchLevel;
import de.infsec.tpl.utils.Utils;
import de.infsec.tpl.utils.WalaUtils;


/**
 * The main data structure for (library/app) profiles
 * @author ederr
 *
 */
public class HashTree implements Serializable {
	private static final long serialVersionUID = 8890771073564530924L;

	private static final Logger logger = LoggerFactory.getLogger(de.infsec.tpl.hash.HashTree.class);
	
	private Config config = new Config();
	
	public enum HTREE_BUILD_VERBOSENESS { 
		MINIMAL /* Root and Package hashes/names only */,
		NORMAL  /* Root/Package/Class hashes including package names (DEFAULT) */,
		DEBUG   /* Root/Package/Class hashes including package/class names */,
		TRACE   /* Root/Package/Class/Method hashes including all names/signatures */
	}

	/**
	 * Build config for HashTree
	 */
	public class Config implements Serializable {
		private static final long serialVersionUID = -8693957635226365553L;

		// if true, filters duplicate method hashes, i.e. methods that have the same fuzzy descriptor
		// this introduces some kind of fuzziness as we abstract from the concrete number of certain descriptor
		public boolean filterDups = false;   
		
		// if true, only public methods are considered during hashing
		// this introduces some fuzziness however better abstracts from internal changes as it better matches the public
		// interfaces used by the developer (e.g. different library versions with the same interface)
		public boolean publicOnly = false;
		
		// if true, inner classes are not considered during hashing
		public boolean filterInnerClasses = false;
		
		// the hash algorithm used for hashing
		public HashAlgorithm hashAlgorithm = HashAlgorithm.MD5;

		public HTREE_BUILD_VERBOSENESS buildVerboseness = HTREE_BUILD_VERBOSENESS.NORMAL;
		
		
		public Config() {}

		public Config(boolean filterDups, boolean publicOnly, boolean filterInnerClasses) {
			this.filterDups = filterDups;
			this.publicOnly = publicOnly;
			this.filterInnerClasses = filterInnerClasses;
		}

		
		public Config(boolean filterDups, boolean publicOnly, boolean filterInnerClasses, HashAlgorithm hashAlgorithm) {
			this(filterDups, publicOnly, filterInnerClasses);
			this.hashAlgorithm = hashAlgorithm;
		}
		
		@Override
		public boolean equals(Object obj) {
			if (!(obj instanceof Config))
				return false;
			Config c = (Config) obj;
			
			return c.filterDups == this.filterDups &&
				   c.publicOnly == this.publicOnly &&
				   c.filterInnerClasses == this.filterInnerClasses &&
				   c.hashAlgorithm.equals(this.hashAlgorithm);
		}
		
		@Override
		public int hashCode() {
			return 10000 * (this.filterDups? 1 : 0) + 1000 * (this.publicOnly? 1 : 0) + 100 * (this.filterInnerClasses? 1 : 0) + hashAlgorithm.value.hashCode(); 
		}
		
		@Override
		public String toString() {
			StringBuilder sb = new StringBuilder("[Config]");
			sb.append("filterDups? " + this.filterDups);
			sb.append(" | publicOnly? " + this.publicOnly);
			sb.append(" | filterInnerClasses: " + this.filterInnerClasses);
			sb.append(" | hash-algo: "+ this.hashAlgorithm);
			return sb.toString();
		}
	}
	
	private Node rootNode;
	
	public class Node implements Serializable {
		private static final long serialVersionUID = 8649289911402320347L;
		
		public byte[] hash;
		public List<Node> childs;
		
		public Node(byte[] hash) {
			this.hash = hash;
			this.childs = new ArrayList<Node>();
		}
		
		@Override
		public boolean equals(Object obj) {
			if (!(obj instanceof Node))
				return false;
			return Hash.equals(((Node) obj).hash, this.hash);
		}
		
		@Override
		public int hashCode() {
			return hash.hashCode() + childs.size();
		}
		
	    @Override
	    public String toString() {
	    	return Hash.hash2Str(this.hash);
	    }

	    public int numberOfChilds() {
	    	return this.childs.size();
	    }

		public void debug() {}
		
	    public String getStats() {
	    	StringBuilder sb = new StringBuilder();
	    	int pNodes = 0;
	    	int cNodes = 0;
	    	int mNodes = 0;
	    	
	    	LinkedList<Node> worklist = new LinkedList<Node>();
	    	worklist.add(this);
	    	Node curNode;
	    	
	    	while (!worklist.isEmpty()) {
	    		curNode = worklist.poll();
	    		worklist.addAll(curNode.childs);

	    		for (Node n: curNode.childs) {
		    		if (n instanceof PackageNode)
		    			pNodes++;
		    		else if (n instanceof ClassNode)
		    			cNodes++;
		    		else if (n instanceof MethodNode)
		    			mNodes++;
		    	}
	    	}
	    	
	    	sb.append("Node stats:\n");
			sb.append(Utils.INDENT + "- contains " + mNodes   + " method hashes.\n");
			sb.append(Utils.INDENT + "- contains " + cNodes    + " clazz hashes.\n");
			sb.append(Utils.INDENT + "- contains " + pNodes + " package hashes.");

	    	return sb.toString();
	    }
	    
	    public boolean isLeaf() {
	    	return childs.isEmpty();
	    }
	}
	
	public class NodeComparator implements Comparator<Node> {
		private ByteArrayComparator comp;
		
		public NodeComparator() throws NoSuchAlgorithmException {
			IHash hashFunc = new HashImpl(config.hashAlgorithm.toString());
			comp = ((Hash) hashFunc).new ByteArrayComparator();
		}
		
		@Override
		public int compare(Node n0, Node n1) {
			return comp.compare(n0.hash, n1.hash);
		}
	}

	
	public class PackageNode extends Node implements Serializable {
		private static final long serialVersionUID = -2824664777266635012L;
		public String packageName;

		public PackageNode(byte[] hash, String packageName) {
			super(hash);
			this.packageName = packageName;
		}

		@Override
		public void debug() {
			logger.info("Debug PackageNode: " + packageName + " (childs: " + childs.size() + ",  " + Hash.hash2Str(hash) + ")");
			for (Node n: this.childs) {
				ClassNode cn = (ClassNode) n;
				logger.info(Utils.INDENT + "- " + cn.clazzName + "  ::  " + cn.numberOfChilds() + "  ::  " + Hash.hash2Str(cn.hash));
//				cn.debug();
			}
		}

		
		public List<Node> getClassNodes() {
			return this.childs;
		}
		
		public List<Node> getMethodNodes() {
			ArrayList<Node> result = new ArrayList<Node>();
			for (Node n: this.childs) {
				result.addAll(((ClassNode) n).getMethodNodes());
			}
			return result;
		}
		
		@Override
		public boolean equals(Object obj) {
			if (!(obj instanceof PackageNode))
				return false;
			
			return Hash.equals(((PackageNode) obj).hash, this.hash);
		}
		
		@Override
		public String toString() {
			return "PNode(" + packageName + ")";
		}
	}
	
	public class ClassNode extends Node implements Serializable {
		private static final long serialVersionUID = 4538829579264140006L;
		public String clazzName;
		
		public ClassNode(byte[] hash, String clazzName) {
			super(hash);
			this.clazzName = clazzName;
		}
		
		public List<Node> getMethodNodes() {
			return this.childs;
		}
		
		@Override
		public void debug() {
			//logger.info("Debug ClassNode: " + clazzName + "  (childs: " + childs.size() + ",  "  + Hash.hash2Human(hash) + ")");
			for (Node n: this.childs) {
				MethodNode mn = (MethodNode) n;
				logger.info(Utils.INDENT2 + "- " + mn.signature + "  ::  " + Hash.hash2Str(mn.hash));
			}
		}

		@Override
		public boolean equals(Object obj) {
			if (!(obj instanceof ClassNode))
				return false;
			
			return Hash.equals(((ClassNode) obj).hash, this.hash);
		}
		
		@Override
		public String toString() {
			return "CNode(" + clazzName + ")";
		}
	}
	
	public class MethodNode extends Node implements Serializable {
		private static final long serialVersionUID = -1147942448831557142L;
		public String signature;
		
		public MethodNode(byte[] hash, String signature) {
			super(hash);
			this.signature = signature;
		}
		
		@Override
		public boolean equals(Object obj) {
			if (!(obj instanceof MethodNode))
				return false;

			return Hash.equals(((MethodNode) obj).hash, this.hash);
		}
		
		@Override
		public String toString() {
			return "MNode(" + signature + ")";
		}
	}
	
	
	
	public enum HashAlgorithm {
		MD5("MD5"), SHA1("SHA-1"), SHA256("SHA-256");
		
		private String value;
		
		HashAlgorithm(String value) {
			this.value = value;
		}
		
		@Override
		public String toString() {
			return this.value;
		}
	};
	
	public static IFilter<IMethod> publicOnlyFilter = new IFilter<IMethod>() {
		@Override
		public Collection<IMethod> filter(Collection<IMethod> input) {
			List<IMethod> result = new ArrayList<IMethod>();
			for (IMethod m: input)
				if (m.isPublic())
					result.add(m);
			
			return result;
		}
		
	};

	
	public HashTree() {}
	

	/*
	 * Setter methods
	 */
	public void setFilterDups(final boolean filterDups) {
		config.filterDups = filterDups;
	}
	
	public void setPublicOnly(final boolean publicOnly) {
		config.publicOnly = publicOnly;
	}
	
	public void setFilterInnerClasses(final boolean filterInnerClasses) {
		config.filterInnerClasses = filterInnerClasses;
	}
	
	public void setHashAlgorithm(final HashAlgorithm algorithm) {
		config.hashAlgorithm = algorithm;
	}

	public void setBuildVerboseness(final HTREE_BUILD_VERBOSENESS v) {
		config.buildVerboseness = v;
	}
	
	public boolean hasDefaultConfig() {
		return !this.config.filterDups && !this.config.filterInnerClasses && !this.config.publicOnly;
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
	
	public Collection<Node> getPackageNodes() {
		return this.getRootNode().childs;
	}
	
	public int getNumberOfPackages() {
		return rootNode.numberOfChilds();
	}
	
	public int getNumberOfClasses() {
		int cCount = 0;
		for (Node pNode: rootNode.childs)
			cCount += getNumberOfClasses((PackageNode) pNode);
		return cCount;
	}
	
	public int getNumberOfClasses(PackageNode pNode) {
		return pNode.numberOfChilds();
	}
	
	public int getNumberOfMethods(PackageNode pNode) {
		int mCount = 0;
		for (Node cNode: pNode.childs)
			mCount += cNode.numberOfChilds();
		return mCount;
	}


	public int getNumberOfMethods() {
		int mCount = 0;
		for (Node pNode: rootNode.childs)
			mCount += getNumberOfMethods((PackageNode) pNode);
		return mCount;
	}
	
	public List<String> getAllMethodSignatures() {
		List<String> signatures = new ArrayList<String>();
		for (Node pNode: rootNode.childs) {
			for (Node cNode: pNode.childs) {
				for (Node mNode: cNode.childs) {
					signatures.add(((MethodNode) mNode).signature);
				}
			}
		}
		Collections.sort(signatures);
		return signatures;
	}

	public int getNumberOfHashesByLevel(MatchLevel lvl) {
		switch(lvl) {
			case CLASS:
				return getNumberOfClasses();
			case METHOD:
				return getNumberOfMethods();
			case PACKAGE:
				return getNumberOfPackages();
		}
		return -1;
	}
	
	public void printConfig() {
		logger.info(config.toString());
	}
	
	public boolean matchesConfig(HashTree hTree) {
		return this.config.equals(hTree.getConfig());
	}

	@Override
	public boolean equals(Object obj) {
		if (!(obj instanceof HashTree))
			return false;
		
		HashTree ht = (HashTree) obj;
		if (!ht.config.equals(this.config))
			return false;
		
		return Hash.equals(this.getRootHash(), ht.getRootHash());
	}

	
	public void generate(boolean filterDups, boolean publicOnly, boolean filterInnerClasses, HashAlgorithm algorithm, IClassHierarchy cha) throws NoSuchAlgorithmException {
		this.config = new Config(filterDups, publicOnly, filterInnerClasses, algorithm);
		generate(cha);
	}
	

		
	/**
	 * Generates a HashTree for every class loaded via application classLoader
	 * @throws NoSuchAlgorithmException
	 */
	public void generate(IClassHierarchy cha) throws NoSuchAlgorithmException {
		logger.debug("Generate library hash tree..");
		if (logger.isDebugEnabled())
			printConfig();
		
		IHash hashFunc = new HashImpl(config.hashAlgorithm.toString());
		NodeComparator comp = new NodeComparator();
		IFilter<IMethod> methodFilter = config.publicOnly? publicOnlyFilter : null;
		
		int classHashCount = 0;
		int methodHashCount = 0;
	
		// create map package name -> list of clazzNodes
		HashMap<String, Collection<ClassNode>> packageMap = new HashMap<String, Collection<ClassNode>>();
		
		for (Iterator<IClass> it = cha.iterator(); it.hasNext(); ) {
			IClass clazz = it.next();
			if (config.publicOnly && !clazz.isPublic())
				continue;			

			if (WalaUtils.isAppClass(clazz)){
				if (config.filterInnerClasses && WalaUtils.isInnerClass(clazz)) {
					continue;
				}
				
				Collection<MethodNode> methodNodes = config.filterDups? new TreeSet<MethodNode>(comp) : new ArrayList<MethodNode>();
				
				Collection<IMethod> methods = clazz.getDeclaredMethods();
				if (methodFilter != null)
					methods = methodFilter.filter(methods);
				
				for (IMethod m: methods) {
					// normalize java|dex bytecode by skipping compiler-generated methods
					if (m.isBridge() || m.isMethodSynthetic()) {
						continue;
					}
					
					byte[] hash = hashFunc.hash(getFuzzyDescriptor(m));
					methodNodes.add(new MethodNode(hash, m.getSignature()));
				}

				// normalization (if we have no methods, either because there are none or due to our filter properties, skip this class)
				if (methodNodes.isEmpty()) {
					logger.trace(Utils.INDENT + ">> No methods found for clazz: " + WalaUtils.simpleName(clazz) + "  [SKIP]");
					continue;
				}
				
				if (!config.filterDups) 
					Collections.sort((List<MethodNode>) methodNodes, comp);  // sort but do not filter dups

				methodHashCount += methodNodes.size();
				classHashCount++;
				
				byte[] clazzHash = hash(methodNodes, hashFunc);
				String classIdentifier = config.buildVerboseness == HTREE_BUILD_VERBOSENESS.DEBUG || config.buildVerboseness == HTREE_BUILD_VERBOSENESS.TRACE? WalaUtils.simpleName(clazz) : "";
				ClassNode clazzNode = new ClassNode(clazzHash, classIdentifier);
				
				// only store method hashes if configured (space vs accuracy)
				clazzNode.childs = config.buildVerboseness == HTREE_BUILD_VERBOSENESS.TRACE? new ArrayList<Node>(methodNodes) : new ArrayList<Node>();
		
				String pckgName = PackageUtils.getPackageName(clazz);
				if (!packageMap.containsKey(pckgName)) {
					packageMap.put(pckgName, config.filterDups? new TreeSet<ClassNode>(comp) : new ArrayList<ClassNode>());
				}
				packageMap.get(pckgName).add(clazzNode);
			}
		}
		
		
		Collection<PackageNode> packageNodes = config.filterDups? new TreeSet<PackageNode>(comp) : new ArrayList<PackageNode>();
		for (String pckgName: new TreeSet<String>(packageMap.keySet())) {
			if (!config.filterDups) 
				Collections.sort((List<ClassNode>) packageMap.get(pckgName), comp);  // sort but do not filter dups
			
			byte[] packageHash = hash(packageMap.get(pckgName), hashFunc);
			PackageNode n = new PackageNode(packageHash, pckgName);
			if (!config.buildVerboseness.equals(HTREE_BUILD_VERBOSENESS.MINIMAL)) // do not add class nodes in min verboseness
				n.childs.addAll(packageMap.get(pckgName));
			packageNodes.add(n);
		}
		
		logger.debug(Utils.INDENT + "- generated " + methodHashCount   + " method hashes.");
		logger.debug(Utils.INDENT + "- generated " + classHashCount    + " clazz hashes.");
		logger.debug(Utils.INDENT + "- generated " + packageNodes.size() + " package hashes.");


		// generate library hash
		if (!config.filterDups) 
			Collections.sort((List<PackageNode>) packageNodes, comp);  // sort but do not filter dups
		
		byte[] libraryHash = hash(packageNodes, hashFunc);
		rootNode = new Node(libraryHash);
		rootNode.childs.addAll(packageNodes);

		logger.debug(Utils.INDENT + "=> Library Hash: " + Hash.hash2Str(libraryHash));
	}
	
	
	public Node getSubTreeByPackage(PackageTree ptree) throws NoSuchAlgorithmException {
		String rootPackage = ptree.getRootPackage();

		// Since we have a flattened tree (in terms of package nodes, we collect all package nodes that
		// equal or start with the rootPackage, then create and return a new rootnode with the collected package nodes
		// as child
		NodeComparator comp = new NodeComparator();
		IHash hashFunc = new HashImpl(config.hashAlgorithm.toString());
		Collection<PackageNode> childs = config.filterDups? new TreeSet<PackageNode>(comp) : new ArrayList<PackageNode>();
		for (Node n: rootNode.childs) {
			PackageNode pn = (PackageNode) n;
			if (pn.packageName.startsWith(rootPackage))
				childs.add(pn);
		}

		if (!config.filterDups) 
			Collections.sort((List<PackageNode>) childs, comp);  // sort but do not filter dups

		// generate new root node
		if (!childs.isEmpty()) {
			Node rootNode = new Node(hash(childs, hashFunc));
			rootNode.childs.addAll(childs);
			return rootNode;
		} else
			return null;  // no matching node found
	}
	
	
	public Node generateRootNode(Collection<PackageNode> pnodes) throws NoSuchAlgorithmException {

		// Since we have a flattened tree (in terms of package nodes, we collect all package nodes that
		// equal or start with the rootPackage, then create and return a new rootnode with the collected package nodes
		// as child
		NodeComparator comp = new NodeComparator();
		IHash hashFunc = new HashImpl(config.hashAlgorithm.toString());
		Collection<PackageNode> childs = config.filterDups? new TreeSet<PackageNode>(comp) : new ArrayList<PackageNode>();
		childs.addAll(pnodes);

		if (!config.filterDups) 
			Collections.sort((List<PackageNode>) childs, comp);  // sort but do not filter dups

		// generate new root node
		if (childs.isEmpty()) {
			logger.warn("[generateRootNode] no childs - return empy rootNode");
		}
		
		Node rootNode = new Node(hash(childs, hashFunc));
		rootNode.childs.addAll(childs);
		return rootNode;
	}
	
	
	
	/**
	 * Generic hash function that takes a list of hashes, concatenates and hashes them
	 * @param hashes  a collection of input hashes
	 * @param hashFunc  a hash function 
	 * @return a hash
	 */
	public static byte[] hash(Collection<? extends Node> nodes, final IHash hashFunc) {
		ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
		
		try {
			for (Node node: nodes)
				outputStream.write(node.hash);
		} catch (IOException e) {
			e.printStackTrace();
		}

		byte[] arr = outputStream.toByteArray();
		return hashFunc.hash(arr);
	}

	
	
	
	
	
	/**
	 * A {@link Descriptor} only describes input arg types + return type, e.g.
	 * The Descriptor of AdVideoView.onError(Landroid/media/MediaPlayer;II)Z  is (Landroid/media/MediaPlayerII)Z
	 * In order to produce a fuzzy (robust against identifier-renaming) descriptor we replace each custom type by a fixed
	 * replacement, e.g. we receive a descriptor like (XII)Z
	 * Note: library dependencies, i.e. lib A depends on lib B are not a problem. If we analyze lib A without loading lib B,
	 * any type of lib B will be loaded with the Application classloader but will _not_ be in the classhierarchy.
	 * @param desc  {@link Descriptor} retrieved from a {@link IMethod}
	 * @return a fuzzy descriptor
	 */
	public static String getFuzzyDescriptor(IMethod m) {
		final String customTypeReplacement = "X";

		logger.trace("[getFuzzyDescriptor]");
		logger.trace("-  signature: " + m.getSignature());
		logger.trace("- descriptor: " + m.getDescriptor().toString());
		
		StringBuilder sb = new StringBuilder("(");
		
		for (int i = (m.isStatic()? 0 : 1) ; i < m.getNumberOfParameters(); i++) {
			boolean isAppClazz = false;

			if (m.getParameterType(i).getClassLoader().equals(ClassLoaderReference.Application)) {
				IClass ct = m.getClassHierarchy().lookupClass(m.getParameterType(i));
				isAppClazz = ct == null || WalaUtils.isAppClass(ct);
				sb.append(isAppClazz? customTypeReplacement : m.getParameterType(i).getName().toString());
			} else
				sb.append(m.getParameterType(i).getName().toString());
			
			//logger.trace(LogConfig.INDENT + "- param ref: " + m.getParameterType(i).getName().toString() + (isAppClazz? "  -> " + customTypeReplacement : "")); 
		}
		//logger.trace("");
		sb.append(")");
		if (m.getReturnType().getClassLoader().equals(ClassLoaderReference.Application)) {
			IClass ct = m.getClassHierarchy().lookupClass(m.getReturnType());
			sb.append(ct == null || WalaUtils.isAppClass(ct)? customTypeReplacement : m.getReturnType().getName().toString());
		} else
			sb.append(m.getReturnType().getName().toString());
		
		logger.trace("-> new type: " + sb.toString());
		return sb.toString();
	}
	
	
	public static HashTree getTreeByConfig(Collection<HashTree> treeList, Config config) {
		for (HashTree lht: treeList)
			if (lht.getConfig().equals(config))
				return lht;
		return null;
	}

	public static HashTree getTreeByConfig(Collection<HashTree> treeList, boolean filterDups, boolean publicOnly, boolean filterInnerClasses) {
		for (HashTree lht: treeList) {
			Config cfg = lht.getConfig();
			if (cfg.filterDups == filterDups && cfg.publicOnly == publicOnly && cfg.filterInnerClasses == filterInnerClasses)
				return lht;
		}
		return null;
	}

	
	public static List<PackageNode> toPackageNode(Collection<Node> col) {
		List<PackageNode> res = new ArrayList<PackageNode>();
		for (Node n: col) {
			if (n instanceof PackageNode)
				res.add((PackageNode) n);
		}
		return res;
	}
	
	
	public static void debug_compareNodes(PackageNode libNode, PackageNode appNode) {
		logger.info("Compare packageNodes:  [LIB] " + libNode.packageName + "  vs  [APP] " + appNode.packageName);

		for (Node n: libNode.childs) {
			if (!appNode.childs.contains(n)) {
				logger.info("  - LibNode:");
				n.debug();

				Node an = debug_getNodeByName(appNode.childs, ((ClassNode) n).clazzName);
				if (an != null) {
					logger.info("  - AppNode:");
					an.debug();
				}
			}
		}
	}
	
	private static Node debug_getNodeByHash(Collection<Node> col, byte[] hash) {
		if (col != null) {
			for (Iterator<Node> it = col.iterator(); it.hasNext(); ) {
				Node n = it.next();
				if (Hash.equals(n.hash, hash))
					return n;
			}
		}
		return null;
	}
	
	private static Node debug_getNodeByName(Collection<Node> col, String clazzName) {
		if (col != null) {
			for (Iterator<Node> it = col.iterator(); it.hasNext(); ) {
				Node n = it.next();
				if (n instanceof ClassNode && (((ClassNode) n).clazzName.equals(clazzName)))
					return n;
			}
		}
		return null;
	}


}
