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

package de.infsec.tpl.hash;

import java.util.Arrays;
import java.util.Comparator;

@Deprecated
public abstract class Hash implements IHash {
	public static boolean equals(byte[] hash1, byte[] hash2) {
		return Arrays.equals(hash1, hash2);
	}
	
	public static String hash2Str(byte[] hash) {
		String format = "%" + (hash.length*2) + "x";
		return String.format(format, new java.math.BigInteger(1, hash));
	}
	
	// Lexicographical comparator for byte arrays
	public class ByteArrayComparator implements Comparator<byte[]> {
		@Override
		public int compare(byte[] left, byte[] right) {
	        for (int i = 0, j = 0; i < left.length && j < right.length; i++, j++) {
	            int a = (left[i] & 0xff);
	            int b = (right[j] & 0xff);
	            if (a != b) {
	                return a - b;
	            }
	        }
	        return left.length - right.length;
		}
	}
	
}
