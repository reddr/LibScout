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

package de.infsec.tpl.resourceparser;

import java.util.Collection;
import com.ibm.wala.classLoader.IClass;

import de.infsec.tpl.utils.Utils;
import de.infsec.tpl.utils.WalaUtils;

/**
 * Data class representing a android view/widget/layout container
 */
public class AndroidView {
	
	protected final int id;
	protected final IClass viewClazz;
	protected final String layoutFile;
	private boolean isSensitive;
	
	public AndroidView(int id, String layoutFile, IClass viewClass) {
		this.id = id;
		this.layoutFile = layoutFile;
		this.viewClazz = viewClass;
	}
	
	public AndroidView(int id, String layoutFile, IClass viewClass, boolean isSensitive) {
		this(id, layoutFile, viewClass);
		this.isSensitive = isSensitive;
	}
	
	public int getID() {
		return this.id;
	}
	
	public String getLayoutFile() {
		return this.layoutFile;
	}
	
	public IClass getViewClass() {
		return this.viewClazz;
	}

	public boolean isAppView() {
		return viewClazz == null? false : WalaUtils.isApplicationClass(viewClazz);
	}
	
	public void setIsSensitive(boolean isSensitive) {
		this.isSensitive = isSensitive;
	}
	
	public boolean isSensitive() {
		return this.isSensitive;
	}
	
	@Override
	public String toString() {
		return toShort() + "  isSensitive: " + isSensitive;
	}
	
	public String toShort() {
		return "User control(" + id + ") in file: " + layoutFile + "  type: " + (viewClazz == null? "unknown" : viewClazz.getName().toString());
	}

	public static Collection<AndroidView> getAppViews(Collection<AndroidView> views) {
		Collection<AndroidView> appViews = Utils.filter(views, new Utils.IPredicate<AndroidView>() {
			@Override
			public boolean apply(AndroidView type) {
				return type.isAppView();
			}
		});
		
		return appViews;
	}
	
	public static Collection<AndroidView> getSensitiveViews(Collection<AndroidView> views) {
		Collection<AndroidView> appViews = Utils.filter(views, new Utils.IPredicate<AndroidView>() {
			@Override
			public boolean apply(AndroidView type) {
				return type.isSensitive();
			}
		});
		
		return appViews;
	}

	public static Collection<AndroidView> getSensitiveAppViews(Collection<AndroidView> views) {
		Collection<AndroidView> appViews = Utils.filter(views, new Utils.IPredicate<AndroidView>() {
			@Override
			public boolean apply(AndroidView type) {
				return type.isSensitive && type.isAppView();
			}
		});
		
		return appViews;
	}

	
	public static AndroidView findViewById(Collection<AndroidView> views, int resId) {
		for (AndroidView view: views) {
			if (view.id == resId)
				return view;
		}
		return null;
	}
	
}
