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

public class HashCode extends Hash {
	public HashCode() {}
	
	@Override
	public byte[] hash(String str) {
		int value = str.hashCode();
	    
		return new byte[] {
            (byte)(value >>> 24),
            (byte)(value >>> 16),
            (byte)(value >>> 8),
            (byte) value};
	}

	@Override
	public byte[] hash(byte[] b) {
		String str = new String(b);
		return hash(str);
	}
	
	
	// adapted from String.hashCode(), generates a 64bit hash
/*	public static long hash(String string) {
	  long h = 1125899906842597L; // prime
	  int len = string.length();

	  for (int i = 0; i < len; i++) {
	    h = 31*h + string.charAt(i);
	  }
	  return h;
	}*/
}
