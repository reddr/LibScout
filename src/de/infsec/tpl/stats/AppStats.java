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

package de.infsec.tpl.stats;

import java.io.File;
import java.util.List;
import java.util.Set;

import de.infsec.tpl.manifest.ProcessManifest;
import de.infsec.tpl.hash.HashTree;
import de.infsec.tpl.pkg.PackageTree;
import de.infsec.tpl.profile.LibProfile;
import de.infsec.tpl.profile.ProfileMatch;


public class AppStats {
	public File appFile;
	public ProcessManifest manifest;
	public boolean isMultiDex;
	
	public PackageTree pTree;
	public List<HashTree> appHashTrees;
		
	public List<LibProfile> profiles;
	public List<ProfileMatch> pMatches;
	public Set<String> packageMatches;
	
	public long processingTime;
	
	
	public AppStats(File appFile) {
		this.appFile  = appFile;
	}
}
