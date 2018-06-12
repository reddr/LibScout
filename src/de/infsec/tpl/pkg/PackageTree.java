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

package de.infsec.tpl.pkg;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ibm.wala.classLoader.IClass;
import com.ibm.wala.ipa.cha.IClassHierarchy;

import de.infsec.tpl.hash.HashTree.PackageNode;
import de.infsec.tpl.utils.Utils;
import de.infsec.tpl.utils.WalaUtils;


public class PackageTree implements Serializable {
	private static final long serialVersionUID = -8286612852897097767L;
	
	private static final Logger logger = LoggerFactory.getLogger(de.infsec.tpl.pkg.PackageTree.class);
	private Node rootNode;
	
	public class Node implements Serializable {
		private static final long serialVersionUID = -2117889548993263279L;
		
		public String name;
		public int clazzCount;
		public List<Node> childs;
		
		public Node(String name) {
			this.name = name;
			this.clazzCount = 0;
			this.childs = new ArrayList<Node>();
		}
		
		public int getNumberOfLeafNodes() {
			int result = 0;
			for (Node child: childs)
				if (child.isLeaf()) result++;
			return result;
		}
		
		@Override
		public boolean equals(Object obj) {
			if (!(obj instanceof Node))
				return false;
			return ((Node) obj).name.equals(this.name);
		}
		
		public void print(boolean includeClazzCount) {
		    print("", true, includeClazzCount);
		}
		
	    private void print(String prefix, boolean isTail, boolean includeClazzCount) {
	        logger.info(prefix + (isTail ? "└── " : "├── ") + name + (includeClazzCount && clazzCount > 0? " (" + clazzCount + ")" : ""));

	        for (int i = 0; i < childs.size(); i++) {
	            childs.get(i).print(prefix + (isTail ? "    " : "│   "), i == childs.size()-1, includeClazzCount);
	        }
	    }
	    
	    @Override
	    public String toString() {
	    	return this.name;
	    }
	    
	    public boolean hasClasses() {
	    	return this.clazzCount > 0;
	    }
	    
	    public boolean isLeaf() {
	    	return childs.isEmpty();
	    }
	}
	
    
    /**
     * Alternative style for a copy constructor, using a static newInstance
     * method.
     */
    public Node newNodeInstance(Node nNode) {
    	Node n = this.new Node(nNode.name);
    	n.clazzCount = nNode.clazzCount;
    	return n;
    }
	
	
	public static PackageTree make(IClassHierarchy cha) {
		return make(cha, false);
	}
	
	public static PackageTree make(IClassHierarchy cha, boolean appClassesOnly) {
		return make(cha, appClassesOnly, null);
	}
	
	public static PackageTree make(IClassHierarchy cha, boolean appClassesOnly, Set<String> filteredPackages) {
		PackageTree tree = new PackageTree();
		for (Iterator<IClass> it = cha.iterator(); it.hasNext(); ) {
			IClass clazz = it.next();
			if (!appClassesOnly || (appClassesOnly && WalaUtils.isAppClass(clazz))) {
				if (filteredPackages == null || !filteredPackages.contains(PackageUtils.getPackageName(clazz)))
					tree.update(clazz);
			}
		}
		return tree;
		
	}

	/**
	 * Generate PackageTree with class name references provided as
	 * collection of {@link IClass}, {@link String}, or {@link PackageNode} objects.
	 * @param col  Collection of {@link IClass}, {@link String}, or {@link PackageNode} objects
	 * @return {@link PackageTree} instance
	 */
	public static PackageTree make(Collection<?> col) {
		PackageTree tree = new PackageTree();
		for (Object o: col) {
			if (o instanceof IClass)
				tree.update((IClass) o);
			else if (o instanceof String)
				tree.update((String) o, true);
			else if (o instanceof PackageNode)
				tree.update(((PackageNode) o).packageName, false);
		}

		return tree;
	}

	
	
	private PackageTree() {
		this.rootNode = new Node("Root");
	}

	@Override
	public boolean equals(Object obj) {
		if (!(obj instanceof PackageTree))
			return false;
		
		// compare list of all package names
		PackageTree pt = (PackageTree) obj;
		return new TreeSet<String>(pt.getAllPackages()).equals(new TreeSet<String>(this.getAllPackages()));
	}
	
	@Override
	public String toString() {
		return getRootPackage();
	}
	
	public void print(boolean includeClazzCount) {
		logger.info("Root Package: " + (getRootPackage() == null? " - none -" : getRootPackage()));
		
		if (rootNode.childs.size() == 1 && !rootNode.hasClasses())
			rootNode.childs.get(0).print(includeClazzCount);
		else
			rootNode.print(includeClazzCount);
	}

	/**
	 * Dump package names that contain at least one class
	 * @return  a mapping from package name to number of included classes
	 */
	public Map<String, Integer> getPackages() {
		return getPackages(rootNode, "", false);
	}
	
	/**
	 * Dump <b>all</b> package names encoded in the tree
	 * @return  an ordered set of package names
	 */
	public Set<String> getAllPackages() {
		return getPackages(rootNode, "", true).keySet();
	}

	public int getNumberOfNonEmptyPackages() {
		return getPackages().keySet().size();
	}
	
	public int getNumberOfAppClasses() {
		Map<String, Integer> packages = getPackages();
		int count = 0;
		for (int c: packages.values())
			count += c;
		return count;
	}

	
	/**
	 * Determine root package of the tree (if any). Expands to the longest unique package name.
	 * Note: This method only works for libraries. It's not applicable to apps since there are many different namespaces/libraries involved.
	 * @return  the unique root package name or null otherwise
	 */
	public String getRootPackage() {
		String rootPackage = "";
		Node curNode = rootNode;

		// This is another heuristic to determine the proper root package in presence of another lib dependency
		// whose package name differs at depth 1 or at depth 2 if depth 1 is some common namespace
		if (rootNode.childs.size() > 1 || 
		   (rootNode.childs.size() == 1 && (rootNode.childs.get(0).name.equals("com") || 
				                            rootNode.childs.get(0).name.equals("de") || 
				                            rootNode.childs.get(0).name.equals("org")))) {
			
			if (rootNode.childs.size() == 1) {
				curNode = rootNode.childs.get(0);
				rootPackage += curNode.name;
			}
			
			int id = 0;
			int max = 0;
			// determine largest subtree in terms of packages
			for (int i = 0; i < curNode.childs.size(); i++) {
				int tmp = getPackages(curNode.childs.get(i), "", true).size();
				if (tmp > max) {
					id = i;
					max = tmp;
				}
			}

			curNode = curNode.childs.get(id);
			rootPackage += (rootPackage.isEmpty()? "" : ".") + curNode.name;
			
			if (curNode.hasClasses())
				return rootPackage.isEmpty()? null : rootPackage;
		}
		
		while (curNode.childs.size() == 1) {
			curNode = curNode.childs.get(0);
			rootPackage += (rootPackage.isEmpty()? "" : ".") + curNode.name;
			
			if (curNode.hasClasses()) break;
		}

		// disallow incomplete root packages of depth 1 that start with common namespace 
		if (rootPackage.equals("com") || rootPackage.equals("de") || rootPackage.equals("org")) {
			rootPackage = "";
		}
		
		return rootPackage.isEmpty()? null : rootPackage;
	}

	
	private Map<String, Integer> getPackages(Node n, String curPath, boolean dumpAllPackages) {
		TreeMap<String, Integer> res = new TreeMap<String, Integer>();
		
		if (n.hasClasses() || dumpAllPackages)
			res.put(curPath + n.name, n.clazzCount);

		if (!n.isLeaf()) {
			for (Node c: n.childs) {
				res.putAll(getPackages(c, curPath + (n.name.equals("Root")? "" : n.name + "."), dumpAllPackages));
			}
		}

		return res;
	}


	/**
	 * Retrieve longest matching node that does not contain classes
	 * @param packageName
	 * @return 
	 */
	public String locateRootPackageForPackageName(String packageName) {
		List<String> struct = PackageUtils.parsePackage(packageName, true);  // TODO: check second arg

		List<String> result = new ArrayList<String>();
		Node curNode = rootNode;
		for (int i = 0; i < struct.size(); i++) {
			Node n = matchChilds(curNode, struct.get(i));
			
			if (n != null) {
				if (n.hasClasses())
					return Utils.join(result, ".");
				else {
					curNode = n;
					result.add(n.name);
				}
			} else {
				return null;
			}
		}
	
		return Utils.join(result, ".");
	}

	public String assemblePackage(List<Node> path) {
		ArrayList<String> pckgToken = new ArrayList<String>();
		for (Node n: path) {
			pckgToken.add(n.name);
		}
		
		return Utils.join(pckgToken, ".");
	}
	
	public Node locateNodeByPackage(String packageName) {
		List<String> struct = PackageUtils.parsePackage(packageName, true);   // TODO: check second arg

		Node curNode = rootNode;
		for (int i = 0; i < struct.size(); i++) {
			Node n = matchChilds(curNode, struct.get(i));
			
			if (n != null) {
				curNode = n; 
			} else {
				return null;
			}
		}
	
		return curNode;
	}
	
	public boolean containsPackage(String packageName) {
		return locateNodeByPackage(packageName) != null;
	}

	
	public boolean update(String packageName, boolean includesClazz) {
		List<String> struct = PackageUtils.parsePackage(packageName, !includesClazz);  // TODO: check second arg
		return update(struct);
	}


	public boolean update(IClass clazz) {
		List<String> struct = PackageUtils.parsePackage(clazz);
		return update(struct);
	}

	private boolean update(List<String> packageStruct) {
		// update
		Node curNode = rootNode;
		if (packageStruct.isEmpty())
			curNode.clazzCount++;
		else {
			for (int i = 0; i < packageStruct.size(); i++) {
				Node n = matchChilds(curNode, packageStruct.get(i));
				
				if (n != null) {
					curNode = n; 
				} else {
					Node newNode = new Node(packageStruct.get(i));
					curNode.childs.add(newNode);
					curNode = newNode;
				}
				
				if (i == packageStruct.size()-1) {
					curNode.clazzCount++;
				}
			}
		}
	
		return true;
	}
	
	
	
	private Node matchChilds(Node n, String str) {
		for (Node node: n.childs) {
			if (node.name.equals(str))
				return node;
		}
		return null;
	}
	
	
	public void updateTreeClazzCount(IClassHierarchy cha) {
		Set<String> packages = this.getAllPackages();
		
		for (Iterator<IClass> it = cha.iterator(); it.hasNext(); ) {
			IClass clazz = it.next();
			if (WalaUtils.isAppClass(clazz)) {
				if (packages.contains(PackageUtils.getPackageName(clazz))) {
					updateClazzCount(clazz);
				}
			}
		}
		
	}
	
	
	private boolean updateClazzCount(IClass clazz) {
		List<String> struct = PackageUtils.parsePackage(clazz);
		
		// update
		Node curNode = rootNode;
		for (int i = 0; i < struct.size(); i++) {
			curNode = matchChilds(curNode, struct.get(i));
			
			if (curNode == null)
				return false;
		}

		curNode.clazzCount++; 
		return true;
	}
	
	
	
	// match by node name
	public static Node matchSubTreeByName(PackageTree tree, PackageTree searchTree) {
		return findSubTreeInTreeByName(tree.rootNode, searchTree.rootNode);
	}


	private static Node findSubTreeInTreeByName(Node tree, Node testTree) {
		logger.trace("[findSubTreeInTree] orig: " + tree.name + "   test: "+ testTree.name);
   
		if (tree.name.equals(testTree.name)) {
			logger.trace("[findSubTreeInTree]   match children");
			if (matchChildrenByName(tree, testTree)) {
				return tree;
			}
		}

		Node result = null;
		logger.trace("non-match -> test childs:");	
		for (Node child : tree.childs) {
			logger.trace(Utils.INDENT + "- test child: " + child.name);	    		
			result = findSubTreeInTreeByName(child, testTree);
	
			if (result != null) {
				if (matchChildrenByName(tree, result)) {
					return result;
				}
			}
		}
	
		return result;
	}

	    
    private static boolean matchChildrenByName(Node tree, Node testTree) {
    	logger.trace("[matchChildren]  orig: " + tree.name + "  test: " + testTree.name);
    	
    	if (!tree.name.equals(testTree.name) || (tree.childs.size() < testTree.childs.size())) {
    		return false;
    	}

    	// tests whether the complete testTree is in gameTree, however gameTree can have more packages, but not less
    	boolean result;
    	for (int idx = 0; idx < testTree.childs.size(); idx++) {
    		result = false;
    		for (int origIdx = 0; origIdx < tree.childs.size(); origIdx++) {
    			result = matchChildrenByName(tree.childs.get(origIdx), testTree.childs.get(idx));
    			if (result == true) break;
    		}
    		if (result == false) return result;
    	}

    	return true;
    }

	    
	    
    /**
     * Match a given tree in another tree by structure only (i.e. number of children, number of leaf children}
     * @param gameTree  the {@PackageTree} to search in
     * @param searchTree  the test {@PackageTree} that should be matched
     * @return a {@List} of {@PackageTree} in the gameTree that matched the searchTree
     */
    public static List<PackageTree> matchSubTree(PackageTree gameTree, PackageTree searchTree) {
    	List<String> pckg = new ArrayList<String>();  // (partial) package name of a gameTree match
    	for (int i = 0; i < 50; i++) pckg.add("");

    	List<PackageTree> result = new ArrayList<PackageTree>();
    	
    	boolean run = true;
    	Set<String> visited = new TreeSet<String>();

    	List<String> path = new ArrayList<String>();  // current path during recursive descent
    	for (int i = 0; i < 50; i++) path.add("");

    	
    	// search game tree as long as matching subtrees are found and it is not completely traversed
    	while (run) {
    		run = matchChildren(gameTree.rootNode, searchTree.rootNode, 0, pckg, visited, path);
    		
    		if (run) {
    			String packageName = Utils.join(pckg, ".");
    	    	logger.debug("[RESULT] pckg: " + pckg +"      join: " + packageName);
    			visited.add(packageName);  // update list of already found sub trees

    			// reset package struct
    	    	for (int i = 0; i < 50; i++) {
    	    		pckg.set(i, "");
    	    		path.set(i, "");
    	    	}
    			
    	    	PackageTree pt = gameTree.getCopyOfSubTree(packageName);
    	    	result.add(pt);

    	    	logger.debug("DUMP OF SUBTREE:");
    	    	if (logger.isDebugEnabled()) pt.print(true);  // TODO DEBUG
    		}
    	}
    	
    	return result;
    }

	    
    private static boolean matchChildren(final Node gameTree, final Node testTree, final int depth, final List<String> pckg, final Set<String> visited, final List<String> path) {
    	logger.trace(Utils.indent(depth) +"[matchChildren]  orig: " + gameTree.name + "(childs: " + gameTree.childs.size() + " leaves: "+ gameTree.getNumberOfLeafNodes() + ")" + "  test: " + testTree.name + "(childs: + " + testTree.childs.size() + " leaves: "+ testTree.getNumberOfLeafNodes() + ")");
		path.set(depth, gameTree.name);
    	logger.trace(Utils.indent(depth) + "          curPckg: " + Utils.join(path, ".") + "   visited: " + visited);
    	
		for (int i = depth+1; i < path.size(); i++) path.set(i, "");
		if (visited.contains(Utils.join(path, "."))) {
			logger.trace(Utils.indent(depth) + "already visited : " + Utils.join(path, ".") + "  -- stop");
			return false;
		}

    	// game tree may have more childs but not less
    	if (gameTree.childs.size() < testTree.childs.size()) {
    		return false;
    	}
    	
    	if (gameTree.getNumberOfLeafNodes() < testTree.getNumberOfLeafNodes())
    		return false;
 
    	// if number of children and number of children leaf nodes are equal we have a structural match
    	if (gameTree.childs.size() == testTree.childs.size() && gameTree.getNumberOfLeafNodes() == testTree.getNumberOfLeafNodes() && gameTree.childs.size() == gameTree.getNumberOfLeafNodes()) {
    		logger.trace(Utils.indent(depth) + "> same number of children + leaves (" + testTree.getNumberOfLeafNodes() + ")");
    		
// TODO: only add if parent is not single leaf	    		
/*	    		if (!gameTree.childs.isEmpty() && gameTree.childs.size() == gameTree.getNumberOfLeafNodes()) {
	    			logger.trace(LogConfig.indent(depth) + "[>> match true(" + depth + ")] " + gameTree.name);
	    			pckg.set(depth,gameTree.name);
	    		}*/
    		return true;
    	}
    	
    	// tests whether the complete testTree is in gameTree, however gameTree can have more packages, but not less
    	boolean result;
    	for (int idx = 0; idx < testTree.childs.size(); idx++) {
    		result = false;
    		for (int origIdx = 0; origIdx < gameTree.childs.size(); origIdx++) {  // save already visisted node  names by recursionLevel
    			result = matchChildren(gameTree.childs.get(origIdx), testTree.childs.get(idx), depth+1, pckg, visited, path);
    			if (result == true) break;
    		}
    		if (result == false) return result;
    	}

    	if (gameTree.isLeaf() == testTree.isLeaf()) {
    		logger.trace(Utils.indent(depth) + "[>> match true(" + depth + ")] " + gameTree.name);
    		pckg.set(depth,gameTree.name);
    		return true;
    	} else {
    		return false;
    	}
    }


	    
    public PackageTree getSubTree(PackageTree ptree) {
    	return getCopyOfSubTree(ptree.getRootPackage());
    }
	    
	    
    /**
     * Retrieves a copy of the subtree for a given package name
     * @param packageName  package name without class, e.g. "Root.com.foo.bar"
     * @return a {@PackageTree} instance for the subtree that matches the provided package name
     */
    public PackageTree getCopyOfSubTree(String packageName) {
    	// parse provided package
    	List<String> fragments = PackageUtils.parsePackage(packageName, true);  // TODO recheck second arg, precondition!
    	if (fragments.isEmpty())
    		return null;
    	
    	PackageTree subTree = new PackageTree();
    	if (fragments.get(0).equals(this.rootNode.name))
    		subTree.rootNode = newNodeInstance(this.rootNode);
    	Node curSubTreeNode = subTree.rootNode;
    	
    	Node curNode = this.rootNode;
    	for (int i = 1; i < fragments.size(); i++) {
    		Node n = matchChilds(curNode, fragments.get(i));

    		if (n == null)
    			return subTree;
    		else {
    			curNode = n;
    			Node newNode = newNodeInstance(curNode);
    			curSubTreeNode.childs.add(newNode);
    			curSubTreeNode = newNode;
    		}
    	}

    	// copy any remaining subtree
    	copySubTree(curNode, curSubTreeNode);
    	
    	return subTree;
    }

    
	/**
	 * Copies the entire subtree from one node to another node 
	 * @param fromTreeNode the {@Node} to be copied from
	 * @param toTreeNode the {@Node} to copy to
	 */
    public void copySubTree(Node fromTreeNode, Node toTreeNode) {
    	for (Node child: fromTreeNode.childs) {
    		Node copyChild = newNodeInstance(child);
    		if (!child.isLeaf())
    			copySubTree(child, copyChild);
    		toTreeNode.childs.add(copyChild);
    	}
    }
 
}
