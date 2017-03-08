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
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import de.infsec.tpl.utils.Utils;


public class LibraryDescription implements Serializable {
	private static final long serialVersionUID = 8175426582245756480L;

	// library name
	public final String name;

	public final LibraryCategory category;

	// optional version string
	public final String version;
	
	// optional release date
	public final Date date;

	// optional comment
	public final String comment;
	
	
	public static enum LibraryCategory {
		Advertising, Analytics, Android, /*Tracker,*/ SocialMedia, Cloud, Utilities
	}
	
	public LibraryDescription(String name, LibraryCategory category, String version, Date date, String comment) {
		this.name = name;
		this.category = category;
		this.version = version;
		this.date = date;
		this.comment = comment;
	}
	

	public List<String> getDescription() {
		ArrayList<String> result = new ArrayList<String>();
		result.add(Utils.INDENT + "        name: " + this.name);
		result.add(Utils.INDENT + "    category: " + this.category);
		result.add(Utils.INDENT + "     version: " + (this.version != null? this.version : " --"));

		if (this.date != null) {
			SimpleDateFormat formatter = new SimpleDateFormat("dd.MM.yyyy");
			String formattedDate = formatter.format(this.date);
			result.add(Utils.INDENT + "release-date: " + formattedDate);	
		} else
			result.add(Utils.INDENT + "release-date:  --");

		result.add(Utils.INDENT + "     comment: " + (this.comment != null? this.comment : " --"));
		return result;
	}
	
	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder("Library Description:\n");
		for (String line: getDescription()) {
			sb.append(line + "\n");
		}
		return sb.toString();
	}
	
	public String getFormattedDate() {
		if (this.date != null) {
			SimpleDateFormat formatter = new SimpleDateFormat("dd.MM.yyyy");
			return formatter.format(this.date);
		} else {
		 	return "---";
		}
	}
}
