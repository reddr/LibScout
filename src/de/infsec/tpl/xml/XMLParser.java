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

package de.infsec.tpl.xml;

import java.io.File;
import java.io.IOException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import de.infsec.tpl.profile.LibraryDescription;
import de.infsec.tpl.profile.LibraryDescription.LibraryCategory;

/**
 * Parser for custom library.xml format (that includes lib meta-data)
 *
 *	<?xml version=\"1.0\"?>
 *	<library>
 *	    <!-- library name --> 
 *	    <name>{}</name>
 *	
 *	    <!-- Advertising, Analytics, Android, SocialMedia, Cloud, Utilities --> 
 *	    <category>{}</category>
 *	
 *	    <!-- optional: version string --> 
 *	    <version>{}</version>
 *	
 *	    <!-- optional: date (format: DD/MM/YYYY)
 *	    <releasedate>{}</releasedate>
 *	
 *	    <!-- optional: comment --> 
 *	    <comment>{}</comment>
 *	</library>
 * 
 * @author ederr
 *
 */
public class XMLParser {
	private static final String TAG_NAME = "name";
	private static final String TAG_VERSION = "version";
	private static final String TAG_CATEGORY = "category";
	private static final String TAG_DATE = "releasedate";
	private static final String TAG_COMMENT = "comment";
	
	
	public static LibraryDescription readLibraryXML(File file) throws ParserConfigurationException, SAXException, IOException, ParseException {
		if (file == null || !file.exists() || file.isDirectory())
			throw new IOException("Library description file does not exist or is a directory!");
		
		DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
		DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
		
		Document doc = dBuilder.parse(file);
		doc.getDocumentElement().normalize();
						
		NodeList nList = doc.getElementsByTagName("library");
		if (nList.getLength() != 1)
			throw new SAXException("The library description file must only contain one <library> root node (found: " + nList.getLength() + ")");
		
		// We only require one description per library
		Node nNode = nList.item(0);
							
		if (nNode.getNodeType() == Node.ELEMENT_NODE) {
			Element element = (Element) nNode;

			// mandatory values
			String name = element.getElementsByTagName(TAG_NAME).item(0).getTextContent();
			
			LibraryCategory category;
			try {
				String catStr = element.getElementsByTagName(TAG_CATEGORY).item(0).getTextContent();
				if (catStr.equals("Social Media") || catStr.equals("Social-Media") || catStr.equals("SocialMedia"))
					category = LibraryCategory.SocialMedia;
				else
					category = LibraryCategory.valueOf(catStr);
			} catch (IllegalArgumentException e) {
				throw new ParseException("Found unknown category: " + element.getElementsByTagName(TAG_CATEGORY).item(0).getTextContent() + "  in file: " + file, -1);
			}
			
			// optional values
			String version = null;
			if (element.getElementsByTagName(TAG_VERSION).getLength() > 0)
				version = element.getElementsByTagName(TAG_VERSION).item(0).getTextContent();
			
			Date date = null;
			if (element.getElementsByTagName(TAG_DATE).getLength() > 0) {
				String dateStr = element.getElementsByTagName(TAG_DATE).item(0).getTextContent();
				if (!dateStr.isEmpty()) {
					SimpleDateFormat formatter = new SimpleDateFormat("dd.MM.yyyy");
					date = formatter.parse(dateStr);
				}
			}
			
			String comment = null;
			if (element.getElementsByTagName(TAG_COMMENT).getLength() > 0)
				comment = element.getElementsByTagName(TAG_COMMENT).item(0).getTextContent();
			
			return new LibraryDescription(name, category, version, date, comment);
		} else
			throw new SAXException("Root node (" + nNode.getNodeName() + " / " + nNode.getNodeValue() + ") is not an element-node");
		
	}
}
