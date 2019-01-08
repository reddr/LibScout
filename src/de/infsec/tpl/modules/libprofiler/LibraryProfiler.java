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

package de.infsec.tpl.modules.libprofiler;

import java.io.File;
import java.io.IOException;
import java.text.ParseException;
import java.util.List;
import java.util.jar.JarFile;

import javax.xml.parsers.ParserConfigurationException;

import de.infsec.tpl.config.LibScoutConfig;
import de.infsec.tpl.hashtree.HashTree;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.xml.sax.SAXException;

import com.ibm.wala.ipa.callgraph.AnalysisScope;
import com.ibm.wala.ipa.cha.ClassHierarchy;
import com.ibm.wala.ipa.cha.ClassHierarchyException;
import com.ibm.wala.ipa.cha.IClassHierarchy;
import com.ibm.wala.types.ClassLoaderReference;

import de.infsec.tpl.pkg.PackageTree;
import de.infsec.tpl.profile.LibProfile;
import de.infsec.tpl.profile.LibraryDescription;
import de.infsec.tpl.profile.Profile;
import de.infsec.tpl.utils.AarFile;
import de.infsec.tpl.utils.Utils;
import de.infsec.tpl.utils.WalaUtils;
import de.infsec.tpl.xml.XMLParser;


public class LibraryProfiler {
	private static final Logger logger = LoggerFactory.getLogger(LibraryProfiler.class);
	
	public static String FILE_EXT_LIB_PROFILE = "libv";   // single library version profile
	
	private File libraryFile;             // library.jar || library.aar
	private LibraryDescription libDesc;   // library description parsed from an XML file


	public static void extractFingerPrints(File libraryFile, File libDescriptionFile) throws ParserConfigurationException, SAXException, IOException, ParseException, ClassHierarchyException, ClassNotFoundException {
		new LibraryProfiler(libraryFile,libDescriptionFile).extractFingerPrints();
	}


	private LibraryProfiler(File libraryFile, File libDescriptionFile) throws ParserConfigurationException, SAXException, IOException, ParseException {
		this.libraryFile = libraryFile;
		
		// read library description
		libDesc = XMLParser.readLibraryXML(libDescriptionFile);
		
		// set identifier for logging
		String logIdentifier = LibScoutConfig.logDir.getAbsolutePath() + File.separator;
		logIdentifier += libDesc.name.replaceAll(" ", "-") + "_" + libDesc.version;
		
		MDC.put("appPath", logIdentifier);
	}

		
	private void extractFingerPrints() throws IOException, ClassHierarchyException, ClassNotFoundException {
		long starttime = System.currentTimeMillis();
		
		logger.info("Process library: " + libraryFile.getName());
		logger.info("Library description:");
		for (String desc: libDesc.getDescription())
			logger.info(desc);
		
		// create analysis scope and generate class hierarchy
		final AnalysisScope scope = AnalysisScope.createJavaAnalysisScope();
		
		JarFile jf = libraryFile.getName().endsWith(".aar")? new AarFile(libraryFile).getJarFile() : new JarFile(libraryFile); 
		scope.addToScope(ClassLoaderReference.Application, jf);
		scope.addToScope(ClassLoaderReference.Primordial, new JarFile(LibScoutConfig.pathToAndroidJar));

		IClassHierarchy cha = ClassHierarchy.make(scope);
		WalaUtils.getChaStats(cha);
		
		// cleanup tmp files if library input was an .aar file
		if (libraryFile.getName().endsWith(".aar")) {
			File tmpJar = new File(jf.getName());
			tmpJar.delete();
			logger.debug(Utils.indent() + "tmp jar-file deleted at " + tmpJar.getName());
		}
		
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
			
		// serialize lib profiles to disk (<profilesDir>/<lib-category>/libName_libVersion.lib)
		logger.info("");
		File targetDir = new File(LibScoutConfig.profilesDir + File.separator + libDesc.category.toString());
		logger.info("Serialize library fingerprint to disk (dir: " + targetDir + ")");
		String proFileName = libDesc.name.replaceAll(" ", "-") + "_" + libDesc.version + "." + FILE_EXT_LIB_PROFILE;
		LibProfile lp = new LibProfile(libDesc, pTree, hTrees);
		
		Utils.object2Disk(new File(targetDir + File.separator + proFileName), lp);
		
		logger.info("");
		logger.info("Processing time: " + Utils.millisecondsToFormattedTime(System.currentTimeMillis() - starttime));
	}

}
