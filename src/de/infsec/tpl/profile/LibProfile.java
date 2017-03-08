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
import java.util.Collection;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import de.infsec.tpl.hash.HashTree;
import de.infsec.tpl.pkg.PackageTree;
import de.infsec.tpl.utils.Pair;

/**
 * A LibProfile instance includes any information about a particular version of a library.
 * This includes parsed meta data as well as generated package/hash-trees.
 * @author ederr
 */

public class LibProfile extends Profile implements Serializable {
	private static final long serialVersionUID = 7810050746806720101L;

	public static LibProfileComparator comp = new LibProfileComparator();
	
	// basic facts about the library, read from XML file
	public LibraryDescription description;
	private boolean isDeprecated = true;   // flag to indicate if this is the most current version of a library (according to our DB)
	
	public LibProfile(final LibraryDescription desc, final PackageTree packageTree, final List<HashTree> hashTrees) {
		super(packageTree, hashTrees);
		this.description = desc;
	}
	
	@Override
	public String toString() {
		return this.description.name + " (" + this.description.version + ")";
	}
	
	public boolean isDeprecatedLib() {
		return isDeprecated;
	}
	
	public void setIsDeprecatedLib(boolean isDeprecated) {
		this.isDeprecated = isDeprecated;
	}
	
	// TODO: if same lib compare releasedates if available, otherwise version
	public static class LibProfileComparator implements Comparator<LibProfile> {
		@Override
		public int compare(LibProfile p0, LibProfile p1) {
			if (p0.description.name.equals(p1.description.name)) {
				return p0.description.version.compareTo(p1.description.version);
			}

			return p0.description.name.compareTo(p1.description.name);
		}
	}
	
	
	// TODO: use SemVer instead of custom versionComp
	public static Map<String,String> getUniqueLibraries(Collection<LibProfile> profiles) {
		HashMap<String,String> result = new HashMap<String,String>();
		for (LibProfile p: profiles) {
			if (!result.containsKey(p.description.name))
				result.put(p.description.name, p.description.version);
			else {
				int comp = versionCompare(result.get(p.description.name), p.description.version);
				if (comp < 0)
					result.put(p.description.name, p.description.version);
			}
		}
		return result;
	}

	
	/**
	 * Compares two version strings. 
	 * 
	 * Use this instead of String.compareTo() for a non-lexicographical 
	 * comparison that works for version strings. e.g. "1.10".compareTo("1.6").
	 * 
	 * @note It does not work if "1.10" is supposed to be equal to "1.10.0".
	 * 
	 * @param str1 a string of ordinal numbers separated by decimal points. 
	 * @param str2 a string of ordinal numbers separated by decimal points.
	 * @return The result is a negative integer if str1 is _numerically_ less than str2. 
	 *         The result is a positive integer if str1 is _numerically_ greater than str2. 
	 *         The result is zero if the strings are _numerically_ equal.
	 */
	public static int versionCompare(String v1, String v2) {
		try {
		    String[] vals1 = v1.split("\\.");
		    String[] vals2 = v2.split("\\.");
	
		    // set index to first non-equal ordinal or length of shortest version string
		    int i = 0;
		    while (i < vals1.length && i < vals2.length && vals1[i].equals(vals2[i])) {
		    	i++;
		    }
		    
		    // compare first non-equal ordinal number
		    if (i < vals1.length && i < vals2.length) {
		        int diff = Integer.valueOf(vals1[i]).compareTo(Integer.valueOf(vals2[i]));
		        return Integer.signum(diff);
		    }
		    
		    // the strings are equal or one string is a substring of the other
		    // e.g. "1.2.3" = "1.2.3" or "1.2.3" < "1.2.3.4"
		    else {
		        return Integer.signum(vals1.length - vals2.length);
		    }
		} catch (NumberFormatException e) {
			return 0;
		}
	}
	
	
	
	public Pair<String,String> getLibIdentifier() {
		return new Pair<String,String>(description.name, description.version);
	}
}
