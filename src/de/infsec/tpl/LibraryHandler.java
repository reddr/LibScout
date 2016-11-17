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

package de.infsec.tpl;

import java.io.File;
import java.io.IOException;
import java.text.ParseException;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.jar.JarFile;

import javax.xml.parsers.ParserConfigurationException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.xml.sax.SAXException;

import com.ibm.wala.classLoader.IClass;
import com.ibm.wala.classLoader.IMethod;
import com.ibm.wala.ipa.callgraph.AnalysisScope;
import com.ibm.wala.ipa.cha.ClassHierarchy;
import com.ibm.wala.ipa.cha.ClassHierarchyException;
import com.ibm.wala.ipa.cha.IClassHierarchy;
import com.ibm.wala.types.ClassLoaderReference;

import de.infsec.tpl.utils.AndroidClassType;
import de.infsec.tpl.TplCLI.CliOptions;
import de.infsec.tpl.hash.HashTree;
import de.infsec.tpl.pkg.PackageTree;
import de.infsec.tpl.profile.LibProfile;
import de.infsec.tpl.profile.LibraryDescription;
import de.infsec.tpl.profile.Profile;
import de.infsec.tpl.utils.Utils;
import de.infsec.tpl.utils.WalaUtils;
import de.infsec.tpl.xml.XMLParser;



/**
 * @author Erik Derr
 */


public class LibraryHandler implements Runnable {
	private static final Logger logger = LoggerFactory.getLogger(de.infsec.tpl.LibraryHandler.class);
	
	private File targetFile;          // target file either library.jar or app.apk, depending on the mode
	private File libDescriptionFile;  // xml file with basic facts about the library (only in non-matching mode)
	private LibraryDescription libDesc;
	private IClassHierarchy cha;
	private List<LibProfile> libProfiles;
	
	public LibraryHandler(File targetFile, File libDescriptionFile, List<LibProfile> profiles) {
		this.targetFile = targetFile;
		this.libDescriptionFile = libDescriptionFile;
		this.libProfiles = profiles;
	}
	
	@Override
	public void run() {
		try {
			init(!CliOptions.isMatchingMode);
			
			if (CliOptions.isMatchingMode) {
				new LibraryIdentifier(targetFile).identifyLibraries(libProfiles);
			} else {
				extractFingerPrints();
			}
		} catch (Throwable t) {
			logger.error("[FATAL " + (t instanceof Exception? "EXCEPTION" : "ERROR") + "] analysis aborted: " + t.getMessage());
			logger.error(Utils.stacktrace2Str(t));
		}
	}

	
	public void init(boolean readLibXML) throws ParserConfigurationException, SAXException, IOException, ParseException {
		// read library description
		if (readLibXML)
			libDesc = XMLParser.readLibraryXML(libDescriptionFile);
		
		
		String logIdentifier = CliOptions.logDir.getAbsolutePath() + File.separator;
		if (readLibXML) {
			logIdentifier += libDesc.name.replaceAll(" ", "-") + "_" + libDesc.version;
		} else {
			logIdentifier +=  targetFile.getName().replaceAll("\\.jar", "").replaceAll("\\.apk", "").replaceAll("\\.aar", "");
		}
		
		// set identifier for log
		MDC.put("appPath", logIdentifier);
	}
	
	
	public void extractFingerPrints() throws IOException, ClassHierarchyException {
		long starttime = System.currentTimeMillis();
		
		logger.info("Process library: " + targetFile.getName());
		logger.info("Library description:");
		for (String desc: libDesc.getDescription())
			logger.info(desc);
		
		// create analysis scope and generate class hierarchy
		final AnalysisScope scope = AnalysisScope.createJavaAnalysisScope();
		
		scope.addToScope(ClassLoaderReference.Application, new JarFile(targetFile));
		scope.addToScope(ClassLoaderReference.Primordial, new JarFile(CliOptions.pathToAndroidJar));

		cha = ClassHierarchy.make(scope);
		
		getChaStats(cha);
		PackageTree pTree = Profile.generatePackageTree(cha);
		if (pTree.getRootPackage() == null) {
			logger.warn(Utils.INDENT + "Library contains multiple root packages");
		}

		List<HashTree> hTrees = Profile.generateHashTrees(cha);

		// if hash tree is empty do not dump a profile
		if (hTrees.isEmpty() || hTrees.get(0).getNumberOfClasses() == 0) {
			logger.error("Empty Hash Tree generated - SKIP");
			return;
		}		
			
		logger.info("");
		File targetDir = new File(CliOptions.profilesDir + File.separator + libDesc.category.toString());
		logger.info("Serialize library fingerprint to disk (dir: " + targetDir + ")");
		File proFile = new File(libDesc.name.replaceAll(" ", "-") + "_" + libDesc.version);
		Utils.serializeObjectToDisk(proFile, targetDir, new LibProfile(libDesc, pTree, hTrees));
		
		logger.info("");
		logger.info("Processing time: " + Utils.millisecondsToFormattedTime(System.currentTimeMillis() - starttime));
	}

	
	public static void getChaStats(IClassHierarchy cha) {
		int clCount = 0;
		int innerClCount = 0;
		int publicMethodCount = 0;
		int miscMethodCount = 0;

		HashMap<de.infsec.tpl.utils.AndroidClassType, Integer> clazzTypes = new HashMap<AndroidClassType, Integer>();
		for (AndroidClassType t: AndroidClassType.values())
			clazzTypes.put(t, 0);

		// collect basic cha information
		for (Iterator<IClass> it = cha.iterator(); it.hasNext(); ) {
			IClass clazz = it.next();

			if (WalaUtils.isAppClass(clazz)) {
				AndroidClassType type = WalaUtils.classifyClazz(clazz);
				clazzTypes.put(type, clazzTypes.get(type)+1);
				logger.trace("App Class: " + WalaUtils.simpleName(clazz) + "  (" + type + ")");

				clCount++;
				if (WalaUtils.isInnerClass(clazz)) innerClCount++;
				
				for (IMethod im: clazz.getDeclaredMethods()) {
					if (im.isBridge() || im.isMethodSynthetic()) continue;
					
					if (im.isPublic()) {
						publicMethodCount++;
					} else {
						miscMethodCount++;
					}
				}
			}
		}

		logger.info("");
		logger.info("= ClassHierarchy Stats =");
		logger.info(Utils.INDENT + "# of classes: " + clCount);
		logger.info(Utils.INDENT + "# thereof inner classes: " + innerClCount);
		for (AndroidClassType t: AndroidClassType.values())
			logger.info(Utils.INDENT2 + t + " : " + clazzTypes.get(t));
		logger.info(Utils.INDENT + "# methods: " + (publicMethodCount + miscMethodCount));
		logger.info(Utils.INDENT2 + "# of public methods: " + publicMethodCount);
		logger.info(Utils.INDENT2 + "# of non-public methods: " + miscMethodCount);
		logger.info("");
	}
	

	
}
