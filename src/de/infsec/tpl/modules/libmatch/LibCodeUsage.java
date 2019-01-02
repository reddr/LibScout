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


package de.infsec.tpl.modules.libmatch;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ibm.wala.classLoader.CallSiteReference;
import com.ibm.wala.classLoader.CodeScanner;
import com.ibm.wala.classLoader.IClass;
import com.ibm.wala.classLoader.IMethod;
import com.ibm.wala.ipa.cha.IClassHierarchy;
import com.ibm.wala.shrikeCT.InvalidClassFileException;

import de.infsec.tpl.hash.AccessFlags;
import de.infsec.tpl.profile.ProfileMatch;
import de.infsec.tpl.utils.Utils;
import de.infsec.tpl.utils.WalaUtils;


/**
 *  Library Code Usage Analysis
 *  Checks which library code is used by the application in terms of API calls
 *  To this end, for each full match (partial matches are excluded) it is checked which calls are used within
 *  the code base that does not belong the identified library root package name.
 */
public class LibCodeUsage {
	private static final Logger logger = LoggerFactory.getLogger(LibCodeUsage.class);
	
	
	// TODO
	// how to deal with libs with ambiguous root pckg (currently excluded)
	//  -> need to check all matched package name for such libs


	public static void checkUsage(final IClassHierarchy cha, final List<ProfileMatch> results) {
		logger.info("");
		logger.info("== Check lib usage ==");
		long starttime = System.currentTimeMillis();

		// get unique libraries (multiple lib versions with an exact match have the same API, thus checking only one of them suffices)
		final HashMap<String,ProfileMatch> lib2Profile = new HashMap<String,ProfileMatch>();  // libname -> profile
		final HashMap<String,String> rootPckg2Lib = new HashMap<String,String>();   // root package -> libname

		for (ProfileMatch pm: results) {
			if (!pm.doAllConfigsMatch()) continue;
			
			String libName = pm.lib.description.name;
			if (!lib2Profile.containsKey(libName)) {
				lib2Profile.put(libName, pm);
			}
			
			String rootPckg = pm.getMatchedPackageTree().getRootPackage();
			
			// TODO: currently exclude libs with ambiguous root packages
			if (!LibraryIdentifier.ambiguousRootPackages.contains(rootPckg) && !rootPckg2Lib.containsKey(rootPckg)) {
				rootPckg2Lib.put(rootPckg, libName);

			}
		}
		
		// shortcut - if there are no lib matches there is no need to walk over the bytecode
		if (lib2Profile.isEmpty()) {
			logger.info(Utils.INDENT + ">> lib code usage analysis done - No libraries matched to scan for (" + Utils.millisecondsToFormattedTime(System.currentTimeMillis() - starttime) + ")");
			return;
		}
		
		// scan code once
		// library root package -> signature, access specifier
		Map<String, TreeMap<String, Integer>> usedMethods = new TreeMap<String, TreeMap<String, Integer>>();
		Map<String, Set<String>> unresolvableMethods = new TreeMap<String, Set<String>>();
		
		// iterate all classes
		for (IClass clazz: cha) {
			if (!WalaUtils.isAppClass(clazz)) continue;
			
			// iterate all methods
			for (IMethod im: clazz.getDeclaredMethods()) {
				if (im.isAbstract() || im.isNative()) continue;

				try { 
					// iterate all call sites
					for (CallSiteReference csr: CodeScanner.getCallSites(im)) {
						
						for (String rootPckg: rootPckg2Lib.keySet()) {
							if (csr.getDeclaredTarget().getSignature().startsWith(rootPckg) && !WalaUtils.simpleName(im.getDeclaringClass()).startsWith(rootPckg)) {
	//TODO how to store? extend DB? flag whether usage was found in app dev code (based on (fractions of) package name) or other lib code?  we could also classify by using matched lib packages								
	// TODO: add additional heuristic to check for app package name levels
								boolean usedInApp = !rootPckg2Lib.keySet().contains(WalaUtils.simpleName(im.getDeclaringClass()));

								// check access specifier for target method
								IClass targetClazz = cha.lookupClass(csr.getDeclaredTarget().getDeclaringClass());
								if (targetClazz == null) { // no lookup possible - dead / legacy code?
									logger.debug(Utils.INDENT + "Unresolvable class for lib method in use: " + csr.getDeclaredTarget().getSignature());
									if (!unresolvableMethods.containsKey(rootPckg2Lib.get(rootPckg)))
										unresolvableMethods.put(rootPckg2Lib.get(rootPckg), new TreeSet<String>());

									unresolvableMethods.get(rootPckg2Lib.get(rootPckg)).add(csr.getDeclaredTarget().getSignature());
									break;
								}

								IMethod targetMethod = targetClazz.getMethod(csr.getDeclaredTarget().getSelector());

								if (targetMethod == null) {  // e.g. if clazz is interface without declared methods
									targetMethod = WalaUtils.resolveMethod(clazz, csr);
								}
								int accessSpecifier = AccessFlags.getMethodAccessCode(targetMethod);
								
								String accessSpec = AccessFlags.flags2Str(accessSpecifier);
								logger.trace(Utils.INDENT + "- method in use (in " + (usedInApp? "app" : "lib") +"): " + csr.getDeclaredTarget().getSignature() + "  in bm: "+ im.getSignature() + "  access: " + accessSpec);

								
								String normalizedSig = csr.getDeclaredTarget().getSignature();

								// normalize signature if lib root package does not match app lib root package (e.g. due to id renaming)
								if (!rootPckg.equals(lib2Profile.get(rootPckg2Lib.get(rootPckg)).lib.packageTree.getRootPackage())) {
									// replace package name in dot notation
									String r = rootPckg.replaceAll("\\.", "\\\\.");
									String rx = lib2Profile.get(rootPckg2Lib.get(rootPckg)).lib.packageTree.getRootPackage().replaceAll("\\.", "\\\\.");

									// replace arguments in / notation
									String r2 = rootPckg.replaceAll("\\.", "/");
									String rx2 = lib2Profile.get(rootPckg2Lib.get(rootPckg)).lib.packageTree.getRootPackage().replaceAll("\\.", "/");

									normalizedSig = csr.getDeclaredTarget().getSignature().replaceAll(r,rx).replaceAll(r2,rx2);
								}
								
								// update usedMethods
								if (!usedMethods.containsKey(rootPckg2Lib.get(rootPckg)))
									usedMethods.put(rootPckg2Lib.get(rootPckg), new TreeMap<String, Integer>());

								usedMethods.get(rootPckg2Lib.get(rootPckg)).put(normalizedSig, accessSpecifier);
							}
							
						}
					}
				} catch (InvalidClassFileException e) {
					logger.error(Utils.stacktrace2Str(e));
				}
			}
		}

		
		// debug output		
		for (String lib: usedMethods.keySet()) {
			ProfileMatch pm = lib2Profile.get(lib);
			String libRootPckg = pm.lib.packageTree.getRootPackage();

// TODO: currently unresolvable methods and access spec are not stored!			
			// store used methods
			pm.usedLibMethods = new TreeSet<String>(usedMethods.get(lib).keySet());
			
			logger.info("- check lib: " + pm.lib.getLibIdentifier() + "  root package: " + libRootPckg + (!libRootPckg.equals(pm.getMatchedPackageTree().getRootPackage())? "  vs  matched root package: " + pm.getMatchedPackageTree().getRootPackage() : ""));
			
			// retrieve number of unique lib classes used
			Set<String> uniqueClazzes = new HashSet<String>();
			for (String sig: usedMethods.get(lib).keySet()) {
				uniqueClazzes.add(Utils.getFullClassName(sig));
			}	
			
			logger.info("  (found " + usedMethods.get(lib).size() + " unique library methods and " + uniqueClazzes.size() + " unique lib clazzes");
			
			for (String sig: usedMethods.get(lib).keySet()) {
				logger.debug(Utils.INDENT + "- method in use: " + sig +  "  " + AccessFlags.flags2Str(usedMethods.get(lib).get(sig)));
				
			}
			
			// This can happen if a library contains multiple sub-libraries like OrmLite-[android,core,jdbc] and only a subset is profiled.
			if (unresolvableMethods.containsKey(lib)) {
				logger.info("");
				for (String sig: unresolvableMethods.get(lib))
					logger.debug(Utils.INDENT + "!! unresolvable library method in use by app: " + sig);
			}
			
			logger.info("");
		}

		logger.info(Utils.INDENT + ">> lib code usage analysis done (" + Utils.millisecondsToFormattedTime(System.currentTimeMillis() - starttime) + ")");
	}
}

						
