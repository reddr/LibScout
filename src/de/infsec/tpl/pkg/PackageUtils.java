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

package de.infsec.tpl.pkg;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

import com.ibm.wala.classLoader.IClass;

import de.infsec.tpl.utils.Utils;
import de.infsec.tpl.utils.WalaUtils;

public class PackageUtils {
	// Relationship between two packages
	public static enum RELATIONSHIP { PARENT, CHILD, SIBLING, UNRELATED };
	
	public static List<String> parsePackage(IClass clazz) {
		String clazzName = WalaUtils.simpleName(clazz);
		return parsePackage(clazzName);
	}

	public static List<String> parsePackage(String name, boolean includeClazz) {
		String[] struct = name.split("\\.");
		List<String> result = new ArrayList<String>((List<String>)Arrays.asList(struct));
		
		if (includeClazz)
			return result.subList(0, result.size()-1);  // exclude clazz Name
		else
			return result;
	}

	
	public static List<String> parsePackage(String clazzName) {
		return parsePackage(clazzName, true);
	}

	
	public static String getPackageName(IClass clazz) {
		return Utils.join(parsePackage(clazz), ".");
	}
	
	public static String getPackageName(String clazzName) {
		return Utils.join(parsePackage(clazzName), ".");
	}

	
	public static int packageDepth(IClass clazz) {
		return parsePackage(clazz).size();
	}

	public static int packageDepth(String pckgName) {
		String[] struct = pckgName.split("\\.");
		return struct.length;
	}
	
	public static int getMaxDepth(Collection<String> packageNames) {
		int depth = 0;
		for (Iterator<String> it = packageNames.iterator(); it.hasNext(); ) {
			int curDepth = packageDepth(it.next());
			if (curDepth > depth)
				depth = curDepth;
		}
		return depth;
	}
	
	public static String getSubPackageOfDepth(String packageName, int depth) {
		List<String> token = parsePackage(packageName, false);
		if (token.size()-1 >= depth)
			return Utils.join(token.subList(0, depth), ".");
		else
			return null;
	}
	
	/**
	 * Tests relationship of package1 to package2. Packages must be provided without class.
	 * @param packageName1
	 * @param packageName2
	 * @return @{link RELATIONSHIP}
	 */
	public static RELATIONSHIP testRelationship(String packageName1, String packageName2) {
		int p1Depth = packageDepth(packageName1);
		int p2Depth = packageDepth(packageName2);
		
		if (packageName1.startsWith(packageName2) && p1Depth > p2Depth)
			return RELATIONSHIP.PARENT;
		else if (packageName2.startsWith(packageName1) && p2Depth > p1Depth)
			return RELATIONSHIP.CHILD;
		else if (p1Depth == p2Depth && Utils.join(parsePackage(packageName1, false).subList(0, p1Depth-1)).equals(Utils.join(parsePackage(packageName2, false).subList(0, p2Depth-1))))
			return RELATIONSHIP.SIBLING;
		else
			return RELATIONSHIP.UNRELATED;
	}
	
	
}
