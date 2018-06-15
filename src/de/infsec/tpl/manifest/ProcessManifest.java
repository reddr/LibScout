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

package de.infsec.tpl.manifest;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.Serializable;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;
import java.util.TreeSet;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;
import org.xmlpull.v1.XmlPullParser;

import android.content.res.AXmlResourceParser;
import pxb.android.axml.AXMLPrinter;


public class ProcessManifest implements Serializable {
	private static final long serialVersionUID = -6763632946511685516L;

	private static final Logger logger = LoggerFactory.getLogger(de.infsec.tpl.manifest.ProcessManifest.class);
	
	// TODO: make a ParsedManifest class with those values
	private Set<String> entryPointsClasses = new HashSet<String>();
	private String packageName = "";
	private int versionCode = 0;
	private int minSdkVersion = 1;  // if not explicitly set, defaults to 1
	private int targetSdkVersion = 0;  // if not explicitly set, defaults to minSdkValue
	private String sharedUserId = "";
	private String applicationName = "";
	private Set<String> permissions = new TreeSet<String>();
	private Set<String> libDependencies = new HashSet<String>();
	
	public final String MANIFEST_FILENAME = "AndroidManifest.xml";
	
	/**
	 * Opens the given apk file and provides the given handler with a stream for
	 * accessing the contained android manifest file
	 * @param apk The apk file to process
	 * @param handler The handler for processing the apk file
	 * 
	 * @author Steven Arzt
	 * @author Erik Derr
	 */
	private void handleAndroidManifestFile(String apk, IManifestHandler handler) {
		File apkF = new File(apk);
		if (!apkF.exists())
			throw new RuntimeException("file '" + apk + "' does not exist!");

		boolean found = false;
		try {
			ZipFile archive = null;
			try {
				archive = new ZipFile(apkF);
				Enumeration<?> entries = archive.entries();
				while (entries.hasMoreElements()) {
					ZipEntry entry = (ZipEntry) entries.nextElement();
					String entryName = entry.getName();
					// We are dealing with the Android manifest
					if (entryName.equals(MANIFEST_FILENAME)) {
						found = true;
						handler.handleManifest(archive.getInputStream(entry));
						break;
					}
				}
			}
			finally {
				if (archive != null)
					archive.close();
			}
		}
		catch (Exception e) {
			throw new RuntimeException("Error when looking for manifest in apk: " + e);
		}
		if (!found)
			throw new RuntimeException("No manifest file found in apk");
	}
	
	public void loadManifestFile(String apk) {
		handleAndroidManifestFile(apk, new IManifestHandler() {
			
			@Override
			public void handleManifest(InputStream stream) {
				loadClassesFromBinaryManifest(stream);
			}
		});
	}

	
	// TODO TODO: parse meta data
	protected void loadClassesFromBinaryManifest(InputStream manifestIS) {
		try {
			AXmlResourceParser parser = new AXmlResourceParser();
			parser.open(manifestIS);

			int type = -1;
			boolean applicationEnabled = true;
			while ((type = parser.next()) != XmlPullParser.END_DOCUMENT) {
				switch (type) {
					case XmlPullParser.START_DOCUMENT:
						break;
					case XmlPullParser.START_TAG:
						String tagName = parser.getName();
						if (tagName.equals("manifest")) {
							this.packageName = getAttributeValue(parser, "package");
							this.sharedUserId = getAttributeValue(parser, "sharedUserId");
							try {
								this.versionCode = Integer.parseInt(getAttributeValue(parser, "versionCode"));
							} catch (NumberFormatException e) {
								logger.warn("Could not parse versionCode: " + getAttributeValue(parser, "versionCode"));
							}
							// TODO parse shareduser id label if we have a string parser
						} else if (tagName.equals("activity")
								|| tagName.equals("receiver")
								|| tagName.equals("service")
								|| tagName.equals("provider")) {
							// We ignore disabled activities
							if (!applicationEnabled)
								continue;
							String attrValue = getAttributeValue(parser, "enabled");
							if (attrValue != null && attrValue.equals("false"))
								continue;
							
							// Get the class name
							attrValue = getAttributeValue(parser, "name");
							entryPointsClasses.add(expandClassName(attrValue));
						}
						else if (tagName.equals("uses-permission")) {
							String permissionName = getAttributeValue(parser, "name");
							// We probably don't want to do this in some cases, so leave it
							// to the user
							// permissionName = permissionName.substring(permissionName.lastIndexOf(".") + 1);
							this.permissions.add(permissionName);
						}
						else if (tagName.equals("uses-library")) {
							String libraryName = getAttributeValue(parser, "name");
							this.libDependencies.add(libraryName);
						}
						else if (tagName.equals("uses-sdk")) {
							try {
								this.minSdkVersion = Integer.parseInt(getAttributeValue(parser, "minSdkVersion"));
							} catch (NumberFormatException e) {
								logger.warn("Could not parse minSdkVersion: " + getAttributeValue(parser, "minSdkVersion"));
							}
							try {
								this.targetSdkVersion = Integer.parseInt(getAttributeValue(parser, "targetSdkVersion"));
							} catch (NumberFormatException e) { /* targetSdkValue is optional */	}

						}
						else if (tagName.equals("application")) {
							// Check whether the application is disabled
							String attrValue = getAttributeValue(parser, "enabled");
							applicationEnabled = (attrValue == null || !attrValue.equals("false"));
							
							// Get the application name which is also the fully-qualified
							// name of the custom application object
							this.applicationName = getAttributeValue(parser, "name");
							if (this.applicationName != null && !this.applicationName.isEmpty())
								this.entryPointsClasses.add(expandClassName(this.applicationName));
						}
						break;
					case XmlPullParser.END_TAG:
						break;
					case XmlPullParser.TEXT:
						break;
				}
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	/**
	 * Generates a full class name from a short class name by appending the
	 * globally-defined package when necessary
	 * @param className The class name to expand
	 * @return The expanded class name for the given short name
	 */
	private String expandClassName(String className) {
		if (className.startsWith(".")) {
			return this.packageName + className;
		} else if (!className.contains(".")) {  // if only the classname is present without leading dot, Android's manifest parser safely expands the class name as if there was a leading dot
			return this.packageName + "." + className;
		} else {
			return className;
		}
	}

	private String getAttributeValue(AXmlResourceParser parser, String attributeName) {
		for (int i = 0; i < parser.getAttributeCount(); i++)
			if (parser.getAttributeName(i).equals(attributeName))
				return AXMLPrinter.getAttributeValue(parser, i);
		return "";
	}

	protected void loadClassesFromTextManifest(InputStream manifestIS) {
		try {
			DocumentBuilder db = DocumentBuilderFactory.newInstance().newDocumentBuilder();
			Document doc = db.parse(manifestIS);
			
			Element rootElement = doc.getDocumentElement();
			this.packageName = rootElement.getAttribute("package");
			
			NodeList appsElement = rootElement.getElementsByTagName("application");
			if (appsElement.getLength() > 1)
				throw new RuntimeException("More than one application tag in manifest");
			for (int appIdx = 0; appIdx < appsElement.getLength(); appIdx++) {
				Element appElement = (Element) appsElement.item(appIdx);

				this.applicationName = appElement.getAttribute("android:name");
				if (this.applicationName != null && !this.applicationName.isEmpty())
					this.entryPointsClasses.add(expandClassName(this.applicationName));

				NodeList activities = appElement.getElementsByTagName("activity");
				NodeList receivers = appElement.getElementsByTagName("receiver");
				NodeList services  = appElement.getElementsByTagName("service");
				
				for (int i = 0; i < activities.getLength(); i++) {
					Element activity = (Element) activities.item(i);
					loadManifestEntry(activity, "android.app.Activity", this.packageName);
				}
				for (int i = 0; i < receivers.getLength(); i++) {
					Element receiver = (Element) receivers.item(i);
					loadManifestEntry(receiver, "android.content.BroadcastReceiver", this.packageName);
				}
				for (int i = 0; i < services.getLength(); i++) {
					Element service = (Element) services.item(i);
					loadManifestEntry(service, "android.app.Service", this.packageName);
				}
				
				NodeList permissions = appElement.getElementsByTagName("uses-permission");
				for (int i = 0; i < permissions.getLength(); i++) {
					Element permission = (Element) permissions.item(i);
					this.permissions.add(permission.getAttribute("android:name"));
				}
			}			
		}
		catch (IOException ex) {
			logger.error("Could not parse manifest: " + ex.getMessage());
			ex.printStackTrace();
		} catch (ParserConfigurationException ex) {
			logger.error("Could not parse manifest: " + ex.getMessage());
			ex.printStackTrace();
		} catch (SAXException ex) {
			logger.error("Could not parse manifest: " + ex.getMessage());
			ex.printStackTrace();
		}
	}
	
	private void loadManifestEntry(Element activity, String baseClass, String packageName) {
		if (activity.getAttribute("android:enabled").equals("false"))
			return;
		
		String className = activity.getAttribute("android:name");		
		entryPointsClasses.add(expandClassName(className));
	}

	public Set<String> getEntryPointClasses() {
		return this.entryPointsClasses;
	}
	
	public String getApplicationName() {
		return this.applicationName;
	}
	
	public Set<String> getPermissions() {
		return this.permissions;
	}

	public String getPackageName() {
		return this.packageName;
	}
	
	public int getVersionCode() {
		return this.versionCode;
	}
	
	public String getSharedUserId() {
		return this.sharedUserId;
	}
	
	public Set<String> getLibraryDependencies() {
		return this.libDependencies;
	}

	public int getMinSdkVersion() { return this.minSdkVersion; }
	public int getTargetSdkVersion() { return this.targetSdkVersion > 0? this.targetSdkVersion : this.minSdkVersion; }
}
