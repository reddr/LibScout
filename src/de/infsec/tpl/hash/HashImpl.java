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

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;


public class HashImpl extends Hash {
	private final MessageDigest digest;

	/**
	 * Creates a new hash implementation object
	 * @param algorithm  e.g. MD5 or SHA-256
	 * @throws NoSuchAlgorithmException
	 */
	public HashImpl(String algorithm) throws NoSuchAlgorithmException {
		digest = MessageDigest.getInstance(algorithm);  /* e.g. MD5, SHA-256 */
	}
	
	@Override
	public byte[] hash(String str) {
		try {
			digest.update(str.getBytes("UTF-8"));
		} catch (UnsupportedEncodingException e) {
			digest.update(str.getBytes());
		}
		return digest.digest();
	}

	@Override
	public byte[] hash(byte[] b) {
		digest.update(b);
		return digest.digest();
	}
}
