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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import com.ibm.wala.classLoader.IMethod;

import de.infsec.tpl.utils.Utils;

public enum AccessFlags {
	NO_FLAG (0x0, "no-flag"),
    PUBLIC (0x1, "public"),
    PRIVATE (0x2, "private"),
    PROTECTED (0x4, "protected"),
    PACKAGE_PROTECTED (0x8, "package-protected");

    private int value;
    private String accessFlagName;

    //cache the array of all AccessFlags, because .values() allocates a new array for every call
    private final static AccessFlags[] allFlags;
    
    private final static List<Integer> validFlagValues;

    private static HashMap<String, AccessFlags> accessFlagsByName;

    static {
        allFlags = AccessFlags.values();

        validFlagValues = new ArrayList<Integer>();
        for (AccessFlags flag: allFlags)
        	validFlagValues.add(flag.getValue());
        
        accessFlagsByName = new HashMap<String, AccessFlags>();
        for (AccessFlags accessFlag: allFlags) {
            accessFlagsByName.put(accessFlag.accessFlagName, accessFlag);
        }
    }

    private AccessFlags(int value, String accessFlagName) {
        this.value = value;
        this.accessFlagName = accessFlagName;
    }
    
    
    private static String flags2Str(AccessFlags[] accessFlags) {
        int size = 0;
        for (AccessFlags accessFlag: accessFlags) {
            size += accessFlag.toString().length() + 1;
        }

        StringBuilder sb = new StringBuilder(size);
        for (AccessFlags accessFlag: accessFlags) {
            sb.append(accessFlag.toString());
            sb.append(" ");
        }
        if (accessFlags.length > 0) {
            sb.delete(sb.length() - 1, sb.length());
        }
        return sb.toString();
    }

    public static boolean isValidFlag(int code) {
    	return validFlagValues.contains(code);
    }
  
    
    public static String flags2Str(int code) {
    	List<String> matchedFlags = new ArrayList<String>();
    	
    	for (AccessFlags flag: allFlags) {
    		if ((code & flag.value) != 0x0) {
    			matchedFlags.add(flag.accessFlagName + "(" + flag.value + ")");
    		}
    	}
    	
    	return Utils.join(matchedFlags, ",");
    }
    
    public static AccessFlags getAccessFlag(String accessFlag) {
        return accessFlagsByName.get(accessFlag);
    }

    public int getValue() {
        return value;
    }

    public String toString() {
        return accessFlagName;
    }
    
    
	public static int getAccessFlagFilter(AccessFlags... flags) {
		int filter = NO_FLAG.getValue();

		if (flags != null) {
			for (AccessFlags flag: flags) {
				if (!AccessFlags.isValidFlag(flag.getValue())) continue;

				filter |= flag.getValue();
			}
		}
		
		return filter;
	}

	public static int getPublicOnlyFilter() {
		return getAccessFlagFilter(AccessFlags.PRIVATE, AccessFlags.PACKAGE_PROTECTED, AccessFlags.PROTECTED);
	}
	
	
	public static int getMethodAccessCode(IMethod m) {
		int res = 0x0;
		
		if (m.isPublic()) {
			res |= AccessFlags.PUBLIC.getValue();
		} else if (m.isProtected()) {
			res |= AccessFlags.PROTECTED.getValue();
		} else if (m.isPrivate()) {
			res |= AccessFlags.PRIVATE.getValue();
		} else {
			res |= AccessFlags.PACKAGE_PROTECTED.getValue();
		}

		return res;
	}
}
    
