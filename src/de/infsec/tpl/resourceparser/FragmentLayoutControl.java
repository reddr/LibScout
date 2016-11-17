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

package de.infsec.tpl.resourceparser;

import com.ibm.wala.classLoader.IClass;

/**
 * Data class representing a fragment layout control
 *
 */
public class FragmentLayoutControl extends AndroidView {
	private final IClass fragmentClazz;
	
	public FragmentLayoutControl(int id, String layoutFile, IClass viewClazz, IClass fragmentClazz) {
		super(id, layoutFile, viewClazz);
		this.fragmentClazz = fragmentClazz;
	}
	
	
	public void setIsSensitive(boolean isSensitive) {
		throw new UnsupportedOperationException();
	}
	
	public boolean isSensitive() {
		return false;
	}
	
	public String getLayoutFile() {
		return this.layoutFile;
	}
	
	public IClass getFragmentClass() {
		return this.fragmentClazz;
	}
	
	@Override
	public String toString() {
		return "Fragment(" + id + ") in file: " + layoutFile + "  clazz: " + (fragmentClazz == null? "null" : fragmentClazz.getName().toString());
	}
}
