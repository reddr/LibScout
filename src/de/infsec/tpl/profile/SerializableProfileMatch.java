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

import java.util.ArrayList;
import java.util.List;
import java.io.Serializable;

import de.infsec.tpl.hash.HashTree.Config;
import de.infsec.tpl.hash.HashTree.HashAlgorithm;
import de.infsec.tpl.utils.Pair;


public class SerializableProfileMatch implements Serializable {
	private static final long serialVersionUID = -6375317865524765307L;

	public static final int MATCH_ALL_CONFIGS = 10000;   
	public static final int MATCH_SOME_CONFIGS = 1000; 
	public static final int MATCH_PARTIAL = 100;  
	public static final int MATCH_PACKAGENAME = 10;
	public static final int MATCH_NONE = 0;
	
	public final String libName;
	public final String libVersion;
	public final boolean isLibObfuscated;
	public final boolean libRootPackagePresent;
	public final int matchLevel;
	public float simScore = 0f;  // 1f if exact match
	public List<SerializableConfig> matchedConfigs;  // only if some configs match
	
	public SerializableProfileMatch(ProfileMatch pm) {
		this.libName = pm.lib.description.name;
		this.libVersion = pm.lib.description.version;
		this.isLibObfuscated = pm.isLibObfuscated();
		this.libRootPackagePresent = pm.libRootPackagePresent;
		
		if (pm.doAllConfigsMatch()) {
			this.matchLevel = MATCH_ALL_CONFIGS;
			this.simScore = 1f;
		} else if (pm.isPartialMatch()) {
			this.simScore = pm.getHighestSimScore().simScore;

			if (this.simScore > .9f)
				this.matchLevel = MATCH_SOME_CONFIGS;   /// TODO RENAME   
			else if (this.simScore > .6f && this.simScore < .9f)
				this.matchLevel = MATCH_PARTIAL;
			else
				this.matchLevel = MATCH_NONE;
		} else {
			this.matchLevel = MATCH_NONE;
		}
	}
 
	public Pair<String,String> getLibIdentifier() {
		return new Pair<String,String>(libName,libVersion);
	}
	
	public int numberOfMatchingConfigs() {
		// only relevant if some configs match
		return this.matchLevel >> 3 == 1? this.matchLevel - MATCH_SOME_CONFIGS : 0;
	}
	
	
	public List<SerializableConfig> config2Serializable(List<Config> list) {
		ArrayList<SerializableConfig> result = new ArrayList<SerializableConfig>();
		for (Config cfg: list)
			result.add(new SerializableConfig(cfg));
		return result;
	}
	
	public class SerializableConfig implements Serializable {
		private static final long serialVersionUID = 598811301653651626L;
		
		public final boolean filterDups;   
		public final boolean publicOnly;
		public final boolean filterInnerClasses;
		public final HashAlgorithm hashAlgorithm;

		public SerializableConfig(Config cfg) {
			this.filterDups = cfg.filterDups;
			this.publicOnly = cfg.publicOnly;
			this.filterInnerClasses = cfg.filterInnerClasses;
			this.hashAlgorithm = cfg.hashAlgorithm;
		}
	}
}
