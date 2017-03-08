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

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ibm.wala.classLoader.IClass;
import com.ibm.wala.ipa.cha.IClassHierarchy;
import com.ibm.wala.types.ClassLoaderReference;
import com.ibm.wala.types.TypeReference;

import de.infsec.tpl.utils.AndroidClassType;
import de.infsec.tpl.utils.MapUtils;
import de.infsec.tpl.utils.Utils;
import de.infsec.tpl.utils.WalaUtils;
import pxb.android.axml.AxmlReader;
import pxb.android.axml.AxmlVisitor;
import pxb.android.axml.AxmlVisitor.NodeVisitor;
import soot.jimple.infoflow.android.resources.ARSCFileParser;
import soot.jimple.infoflow.android.resources.ARSCFileParser.AbstractResource;
import soot.jimple.infoflow.android.resources.ARSCFileParser.StringResource;
import soot.jimple.infoflow.android.resources.AbstractResourceParser;
import soot.jimple.infoflow.android.resources.IResourceHandler;


/**
 * Parser for analyzing the layout XML files inside an android application
 * 
 * @author Steven Arzt
 * @author Erik Derr
 *
 */
public class LayoutFileParser extends AbstractResourceParser {
	private static final Logger logger = LoggerFactory.getLogger(de.infsec.tpl.resourceparser.LayoutFileParser.class);
	
	private final Map<Integer, AndroidView> androidViews = new HashMap<Integer, AndroidView>();    // control res id to android view
	private final Map<String, List<FragmentLayoutControl>> fragments = new HashMap<String, List<FragmentLayoutControl>>();  // maps a layout filename to a fragment layout control
	private final Map<String, Set<String>> callbackMethods = new HashMap<String, Set<String>>();  // layout file name -> method names
	private final Map<String, Set<String>> includeDependencies = new HashMap<String, Set<String>>();
	
	private final String packageName;
	private final ARSCFileParser resParser;
	
	private final static int TYPE_NUMBER_VARIATION_PASSWORD = 0x00000010;
	private final static int TYPE_TEXT_VARIATION_PASSWORD = 0x00000080;
	private final static int TYPE_TEXT_VARIATION_VISIBLE_PASSWORD = 0x00000090;
	private final static int TYPE_TEXT_VARIATION_WEB_PASSWORD = 0x000000e0;
	
	public LayoutFileParser(String packageName, ARSCFileParser resParser) {
		this.packageName = packageName;
		this.resParser = resParser;
	}
	
	private IClass getLayoutClass(IClassHierarchy cha, String clazzName) {
		// This is due to the fault-tolerant xml parser
		if (clazzName.equals("view")) clazzName = "View";

		IClass iclazz = null;
		if (iclazz == null)
			iclazz = cha.lookupClass(TypeReference.findOrCreate(ClassLoaderReference.Application, Utils.convertToBrokenDexBytecodeNotation(clazzName)));
		if (iclazz == null && !packageName.isEmpty())
			iclazz = cha.lookupClass(TypeReference.findOrCreate(ClassLoaderReference.Application, Utils.convertToBrokenDexBytecodeNotation(packageName + "." + clazzName)));
		if (iclazz == null)
			iclazz = cha.lookupClass(TypeReference.findOrCreate(ClassLoaderReference.Application, Utils.convertToBrokenDexBytecodeNotation("android.widget." + clazzName)));
		if (iclazz == null)	
			iclazz = cha.lookupClass(TypeReference.findOrCreate(ClassLoaderReference.Application, Utils.convertToBrokenDexBytecodeNotation("android.webkit." + clazzName)));
		if (iclazz == null)
			iclazz = cha.lookupClass(TypeReference.findOrCreate(ClassLoaderReference.Application, Utils.convertToBrokenDexBytecodeNotation("android.view." + clazzName)));
		
		// PreferenceScreen, PreferenceCategory, (i)shape, item, selector, scale, corners, solid .. tags are no classes and thus there will be no corresponding layout class
		if (iclazz == null)	
			logger.trace(Utils.INDENT + "Could not find layout class " + clazzName);

		return iclazz;
	}	

	
	private class IncludeParser extends NodeVisitor {
	    private final String layoutFile;

	    public IncludeParser(String layoutFile) {
	        this.layoutFile = layoutFile;
	    }    

	    @Override
	    public void attr(String ns, String name, int resourceId, int type, Object obj) {
	        // Is this the target file attribute?
	        String tname = name.trim();
	        if (tname.equals("layout")) {
	            if (type == AxmlVisitor.TYPE_REFERENCE && obj instanceof Integer) {
	                // We need to get the target XML file from the binary manifest
	                AbstractResource targetRes = resParser.findResource((Integer) obj);
	                if (targetRes == null) {
	                    logger.trace(Utils.INDENT + "Target resource " + obj + " for layout include not found");
	                    return;
	                }    
	                if (!(targetRes instanceof StringResource)) {
	                    logger.trace(Utils.INDENT + "Invalid target node for include tag in layout XML, was " + targetRes.getClass().getName());
	                    return;
	                }    
	                String targetFile = ((StringResource) targetRes).getValue();

	                // If we have already processed the target file, we can
	                // simply copy the callbacks we have found there
	                if (callbackMethods.containsKey(targetFile))
	                    for (String callback : callbackMethods.get(targetFile))
	                        addCallbackMethod(layoutFile, callback);
	                else {
	                    // We need to record a dependency to resolve later
	                    MapUtils.addToSet(includeDependencies, targetFile, layoutFile);
	                }    
	            }    
	        }    

	        super.attr(ns, name, resourceId, type, obj);
	    }    
	}



	/**
	 * Adds a callback method found in an XML file to the result set 
	 * @param layoutFile The XML file in which the callback has been found
	 * @param callback The callback found in the given XML file
	 */
	private void addCallbackMethod(String layoutFile, String callback) {
	    MapUtils.addToSet(callbackMethods, layoutFile, callback);

	    // Recursively process any dependencies we might have collected before
	    // we have processed the target
	    if (includeDependencies.containsKey(layoutFile))
	        for (String target : includeDependencies.get(layoutFile))
	            addCallbackMethod(target, callback);
	}

	

	private class FragmentParser extends LayoutParser {
	    private IClass fragmentClazz = null;
	    private Integer id = -1;

	    public FragmentParser(IClassHierarchy cha, String layoutFile, IClass viewClazz) {
	    	super(cha, layoutFile, viewClazz);
	    }    

 	    @Override
	    public void attr(String ns, String name, int resourceId, int type, Object obj) {
	        String tname = name.trim();
			if (tname.equals("id") && type == AxmlVisitor.TYPE_REFERENCE)
				this.id = (Integer) obj;

			else if ((tname.equals("name") || tname.equals("class") && type == AxmlVisitor.TYPE_STRING && obj instanceof String)) {
				String className = ((String) obj).trim();

				if (className.startsWith(".")) {
					logger.debug("Fragment attr parser::  \"" + tname + "\"  contains leading dot: " + className);
					className = className.substring(1);  // TODO: sometimes the parser adds a leading "."
				}

				// weird we had sth. like "5apperfection.bluebox.ui.fragments.DeviceLinksFragment" although the file included the string "apperfection.bluebox.ui.fragments.DeviceLinksFragment"
				while (!className.substring(0, 1).matches("[a-zA-Z]")) {
					logger.debug("Fragment attr parser::  \"" + tname + "\"  starts with a non-letter character!:  " + className  + "   fixing..");
					className = className.substring(1);
				}
				
	        	try {
	        		fragmentClazz = WalaUtils.lookupClass(cha, className);
	        	} catch (ClassNotFoundException e) {
	        		logger.warn("Could not lookup IClass for Fragment " + className);
	        	}
	        }
    		
	        super.attr(ns, name, resourceId, type, obj);
	    }
	    
		@Override
    	public void end() {
			if (id > 0)
				MapUtils.addValue(fragments, layoutFile, new FragmentLayoutControl(id, layoutFile, clazz, fragmentClazz));
			id = -1;
    	}
	}
	
	
	
	private class LayoutParser extends NodeVisitor {
		protected final IClassHierarchy cha;
		protected final String layoutFile;
		protected final IClass clazz;
    	private Integer id = -1;
    	private boolean isSensitive = false;
    	
    	public LayoutParser(IClassHierarchy cha, String layoutFile, IClass clazz) {
    		this.cha = cha;
    		this.layoutFile = layoutFile;
    		this.clazz = clazz;
    	}

    	@Override
       	public NodeVisitor child(String ns, String name) {
			if (name == null || name.isEmpty()) {
    			logger.trace(Utils.INDENT + "Encountered a null node name or empty node name "
    					+ "in file " + layoutFile + ", skipping node...");
    			return null;
    		}
   			
    		String tname = name.trim();
    		if (tname.equals("include"))       /// TODO NOT SURE IF THIS IS CORRECT, include can occur in the middle of the file, anything afterwards seems not to be parsed anymore
    		   return new IncludeParser(layoutFile);

    		// For layout defined fragments we need the class name that is either specified via the name- or class-tag
    		if (tname.equals("fragment")) 
    			return new FragmentParser(cha, layoutFile, clazz);

    		// The "merge" tag merges the next hierarchy level into the current
    		// one for flattening hierarchies.
    		if (tname.equals("merge"))
    		    return new LayoutParser(cha, layoutFile, clazz);
    		
			final IClass childClass = getLayoutClass(cha, tname);
			if (childClass != null && 
			   (WalaUtils.classifyClazz(childClass) == AndroidClassType.LayoutContainer || WalaUtils.classifyClazz(childClass) == AndroidClassType.View))
       			return new LayoutParser(cha, layoutFile, childClass);
			else
				return super.child(ns, name);
       	}
		        
    	private boolean isAndroidNamespace(String ns) {
    	    if (ns == null)
    	        return false;
    	    ns = ns.trim();
    	    if (ns.startsWith("*"))
    	        ns = ns.substring(1);
    	    if (!ns.equals("http://schemas.android.com/apk/res/android"))
    	        return false;
    	    return true;
    	}
    	
    	@Override
    	public void attr(String ns, String name, int resourceId, int type, Object obj) {
    		// Check that we're actually working on an android attribute
    		if (!isAndroidNamespace(ns)) return;

    		String tname = name.trim();
    		if (tname.equals("id") && type == AxmlVisitor.TYPE_REFERENCE)
    		    this.id = (Integer) obj;
    		else if (tname.equals("password") && type == AxmlVisitor.TYPE_INT_BOOLEAN)
    		    isSensitive = ((Integer) obj) != 0; // -1 for true, 0 for false
    		else if (!isSensitive && tname.equals("inputType") && type == AxmlVisitor.TYPE_INT_HEX) {
    		    int tp = (Integer) obj;
    		    isSensitive = ((tp & TYPE_NUMBER_VARIATION_PASSWORD) == TYPE_NUMBER_VARIATION_PASSWORD)
    		    		   || ((tp & TYPE_TEXT_VARIATION_PASSWORD) == TYPE_TEXT_VARIATION_PASSWORD)
    		               || ((tp & TYPE_TEXT_VARIATION_VISIBLE_PASSWORD) == TYPE_TEXT_VARIATION_VISIBLE_PASSWORD)
    		               || ((tp & TYPE_TEXT_VARIATION_WEB_PASSWORD) == TYPE_TEXT_VARIATION_WEB_PASSWORD);
    		}
    		else if (isActionListener(tname) && type == AxmlVisitor.TYPE_STRING && obj instanceof String) {
       			String strData = ((String) obj).trim();
       			addCallbackMethod(layoutFile, strData);
       		}
    		else {
    		    if (type == AxmlVisitor.TYPE_STRING)
    		        logger.trace(Utils.INDENT + "Found unrecognized XML attribute:  " + tname);
    		}

    		super.attr(ns, name, resourceId, type, obj);
    	}
    	
		/**
    	 * Checks whether this name is the name of a well-known Android listener
    	 * attribute. This is a function to allow for future extension.
    	 * @param name The attribute name to check. This name is guaranteed to
    	 * be in the android namespace.
    	 * @return True if the given attribute name corresponds to a listener,
    	 * otherwise false.
    	 */
    	private boolean isActionListener(String name) {
    		return name.equals("onClick");
    	}

		@Override
    	public void end() {
    		if (id > 0)  // filter views that do not have an Android id
    			androidViews.put(id, new AndroidView(id, layoutFile, clazz, isSensitive));
    	}
	}
	

	/**
	 * Parses all layout XML files in the given APK file and loads the IDs of
	 * the user controls in it.
	 * @param fileName The APK file in which to look for user controls
	 */
	public void parseLayoutFile(final IClassHierarchy cha, final String fileName) {
		handleAndroidResourceFiles(fileName, /*classes,*/ null, new IResourceHandler() {
		
			@Override
			public void handleResourceFile(final String fileName, Set<String> fileNameFilter, InputStream stream) {
				// we only process valid layout XML files
				if (!(fileName.startsWith("res/layout") && fileName.endsWith(".xml"))) {
					return;
				}
				
				// Get the fully-qualified class name
				String entryClass = fileName.substring(0, fileName.lastIndexOf("."));
				if (!packageName.isEmpty())
					entryClass = packageName + "." + entryClass;
				
				// Filter files if desired
				if (fileNameFilter != null) {
					boolean found = false;
					for (String s : fileNameFilter)
						if (s.equalsIgnoreCase(entryClass)) {
							found = true;
							break;
						}
					if (!found)
						return;
				}

				try {
					ByteArrayOutputStream bos = new ByteArrayOutputStream();
					int in;
					while ((in = stream.read()) >= 0)
						bos.write(in);
					bos.flush();
					byte[] data = bos.toByteArray();
					if (data == null || data.length == 0)	// File empty?
						return;
					
					AxmlReader rdr = new AxmlReader(data);
					rdr.accept(new AxmlVisitor() {
						@Override
						public NodeVisitor first(String ns, String name) {
							if (name == null)
								 return new LayoutParser(cha, fileName, null);
							
							final String tname = name.trim();
							final IClass clazz;
							if (tname.isEmpty() || tname.equals("merge") || tname.equals("include"))
								clazz = null;
							else
								clazz = getLayoutClass(cha, tname);

							if (clazz == null || (clazz != null && WalaUtils.classifyClazz(clazz) == AndroidClassType.LayoutContainer))
								return new LayoutParser(cha, fileName, clazz);
							else
								return super.first(ns, name);
						}
					});
				} catch (Exception ex) {
					logger.warn("Could not read binary XML file (" + fileName + "):  " + ex.getMessage());
					ex.printStackTrace();
				}
			}

		});
	}


	/**
	 * Gets all fragments defined in layout XML files. The result is a
	 * mapping from layout file name to the respective fragment layout control.
	 * @return The fragments found in XML files.
	 */
	public Map<String, List<FragmentLayoutControl>> getFragments() {
		return this.fragments;
	}
	

	/**
	 * Gets the views/widgets/layout container found in the layout XML file. The result is a
	 * mapping from the id to the respective layout control.
	 * @return The layout controls found in the XML file.
	 */
	public Map<Integer, AndroidView> getAndroidViews() {
		return this.androidViews;
	}

	/**
	 * Gets the callback methods found in the layout XML file. The result is a
	 * mapping from the file name to the set of found callback methods.
	 * @return The callback methods found in the XML file.
	 */
	public Map<String, Set<String>> getCallbackMethods() {
		return this.callbackMethods;
	}
	
}
