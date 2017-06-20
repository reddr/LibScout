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

package de.infsec.tpl.utils;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;

import org.apache.commons.io.FileUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import de.infsec.tpl.stats.AppStats;
import de.infsec.tpl.stats.SerializableAppStats;


/**
 * Some random utility functions
 * @author Erik Derr
 */
public class Utils {
//	private static final Logger logger = LoggerFactory.getLogger(de.infsec.tpl.TplCLI.class);
	
	// indent for various kinds of messages
	public static final String INDENT = "    ";
	public static final String INDENT2 = INDENT + INDENT;
	public static final String[] INDENTATION;
	
	public enum LOGTYPE { NONE, CONSOLE, FILE };
	
	static {
		INDENTATION = new String[11];
		String curIndent = "";
		for (int i = 0; i < 11; i++) {
			INDENTATION[i] = curIndent;
			curIndent += INDENT;
		}
	}

	public static String indent() {
		return indent(1);
	}
	
	public static String indent(int indentLevel) {
		indentLevel = Math.min(indentLevel, 10);
		indentLevel = Math.max(0, indentLevel);
		return INDENTATION[indentLevel];
	}

	
	
	/**
	 * Converts class name in dex bytecode notation to fully-qualified class name 
	 * @param class name in dex bytcode notation, e.g. "Lcom/ebay/motors/garage/myvehicles/GarageInsertActivity;"
 	 * @return className fully-qualified class name, e.g. "com.ebay.motors.garage.myvehicles.GarageInsertActivity"
	 */
	public static String convertToFullClassName(String className) {
		if (className.startsWith("L")) className = className.substring(1);
		if (className.endsWith(";")) className = className.substring(0, className.length()-1);
		
		return className.replaceAll("/", "\\.");
	}
	


	/**
	 * Converts fully-qualified class name to class name in dex bytecode notation
	 * @param className fully-qualified class name, e.g. "com.motors.myvehicles.GarageInsertActivity"
	 * @return class name in broken dex bytcode notation (trailing ";" is missing), e.g. "Lcom/motors/myvehicles/GarageInsertActivity"
	 * @deprecated once this classname notation mess in the dex frontend is fixed
	 */
	public static String convertToBrokenDexBytecodeNotation(String className) {
		if (className == null) return null;
		return className.startsWith("L")? className : "L" + className.replaceAll("\\.", "/");
	}
	
	
	public static String convertToDexBytecodeNotation(String typeName) {
		if (typeName.isEmpty()) return typeName;
		
		// check if type is array
		int dimension = 0;
		while (typeName.endsWith("[]")) {
			typeName = typeName.substring(0, typeName.length()-2);
			dimension++;
		}
		
		if (TOVARTYPES.containsKey(typeName))
			typeName = TOVARTYPES.get(typeName).toString();
		else
			typeName = "L" + typeName.replaceAll("\\.", "/") + ";";
		
		for (int i = 0; i < dimension; i++)
			typeName = "[" + typeName;
	
		return typeName;
	}
	
	
	/**
	 * Checks whether a given method is a framework method
	 * @param methodSignature
	 * @return true if it's a framework method, false otherwise
	 * 
	 * @deprecated
	 */
	// TODO spaghetti code, to be rewritten
	public static boolean isFrameworkCall(String methodSignature) {
		if (methodSignature.startsWith("java.")           ||    // java packages
			methodSignature.startsWith("Ljava/")           ||    // java packages
			
			methodSignature.startsWith("javax.")          ||    // javax packages
			methodSignature.startsWith("Ljavax/")          ||    // javax packages
			
			methodSignature.startsWith("junit.")          ||    // junit package
			methodSignature.startsWith("Ljunit/")          ||    // junit package
			
		    methodSignature.startsWith("android.")        ||    // android package
		    methodSignature.startsWith("Landroid/")        ||    // android package
		    
		    methodSignature.startsWith("dalvik.")         ||    // dalvik package
		    methodSignature.startsWith("Ldalvik/")         ||    // dalvik package
		    
		    methodSignature.startsWith("org.apache.")     ||    // org.apache.* package
		    methodSignature.startsWith("Lorg/apache/")     ||    // org.apache.* package
		    
		    methodSignature.startsWith("org.json.")       ||    // org.json.* package
		    methodSignature.startsWith("Lorg/json/")       ||    // org.json.* package
		    
		    methodSignature.startsWith("org.w3c.dom.")    ||    // W3C Java bindings for the Document Object Model
		    methodSignature.startsWith("Lorg/w3c/dom/")    ||    // W3C Java bindings for the Document Object Model
		    
		    methodSignature.startsWith("org.xml.sax.")    ||    // core SAX APIs
		    methodSignature.startsWith("Lorg/xml/sax/")    ||    // core SAX APIs
		    
		    methodSignature.startsWith("org.xmlpull.v1.")  ||    // XML Pull Parser
		    methodSignature.startsWith("Lorg/xmlpull/v1/") ||     // XML Pull Parser
		    
		    methodSignature.startsWith("sun.")    ||    // sun
		    methodSignature.startsWith("Lsun/")    ||    // sun

		    methodSignature.startsWith("com.sun.")    ||    // sun
		    methodSignature.startsWith("Lcom/sun/")||    // sun

		    methodSignature.startsWith("libcore.io.")    ||    //  libcore.io
		    methodSignature.startsWith("Llibcore/io/")||    // libcore.io
		    
		    methodSignature.startsWith("Lorg/omg/"))
		    
		    return true;
		else
			return false;
	}
	
	
	
	/**
	 * Returns the full class name of a method signature
	 * @param methodSignature in notation "java.lang.StringBuilder.append(Ljava/lang/String;)"
	 * @return the extracted class substring
	 */
	public static String getFullClassName(String methodSignature) {
		int endIdx = methodSignature.indexOf("(");
		if (endIdx == -1) return methodSignature;
		
		String result = methodSignature.substring(0, endIdx); // strip args and return type
		return result.substring(0, result.lastIndexOf("."));
	}
	


	
	/**
	 * Vartypes used in Dex bytecode and their mnemonics
	 */
	public static final HashMap<Character, String> VARTYPES = new HashMap<Character, String>() {
	    private static final long serialVersionUID = 1L; 
	    {   
	        put ('V', "void");    // can only be used for return types
	        put ('Z', "boolean");
	        put ('B', "byte");
	        put ('S', "short");
	        put ('C', "char");
	        put ('I', "int");
	        put ('J', "long");    // 64 bits
	        put ('F', "float");
	        put ('D', "double");  // 64 bits
	    }   
	};

	/**
	 * Mnemonics to dex bytecode vartypes  
	 */
	public static final HashMap<String, Character> TOVARTYPES = new HashMap<String, Character>() {
	    private static final long serialVersionUID = 1L; 
	    {   
	        put ("void", 'V');    // can only be used for return types
	        put ("boolean", 'Z');
	        put ("byte", 'B');
	        put ("short", 'S');
	        put ("char", 'C');
	        put ("int", 'I');
	        put ("long", 'J');    // 64 bits
	        put ("float", 'F');
	        put ("double", 'D');  // 64 bits
	    }   
	};
	

	public static boolean isPrimitiveType(String type) {
		return TOVARTYPES.containsKey(type) || VARTYPES.containsKey(type.charAt(0));
	}
	
	public static boolean isArrayType(String type) {
		return type.startsWith("[");
	}
	
	public static boolean isParameterRegister(String register) {
		return register.matches("^p\\d{1,4}$");
	}
	
	public static boolean isNormalRegister(String register) {
		return register.matches("^v\\d{1,5}$");
	}

	
	/**
	 * Parses the method argument header of a dex method signature
	 * @param signature   method signature in dex notation
	 * @param humanReadable  if true it converts ther dex vartypes to human readable types
	 * @return an array of (human readable) argument types
	 * 
	 * @deprecated
	 * use IMethodReference directly instead of parsing ourselves (arguments are already parsed in CallInstructions)
	 */
	@Deprecated
	public static List<String> parseMethodArguments(String signature, boolean humanReadable) {
	    ArrayList<String> result = new ArrayList<String>();

	    // Parse arguments
	    String args = signature.substring(signature.indexOf('(')+1, signature.indexOf(')'));
	    Boolean parsingObject = false;
	    String currentStr = "";
	    for (char c: args.toCharArray()) {
	    	currentStr += c;
	    	
	        if (c == 'L') { // start of class object
	            parsingObject = true;
	        } else if (VARTYPES.containsKey(c) && !parsingObject) {  // found var type
	            result.add(humanReadable? VARTYPES.get(c) : currentStr);
	            currentStr = "";
	        } else if (c == ';') {  // end of class object
	            parsingObject = false;
	            result.add(humanReadable? currentStr.substring(1,  currentStr.length()-1).replaceAll("/", ".") : currentStr);
	            currentStr = "";
	        }   
	    }   

	    return result;
	}
	
	
	/**
	 * Strips leading and trailing quotes of strings
	 * @param str  input string
	 * @return dequoted string
	 */
	public static String dequote(String str) {
		if (isConstant(str)) {
			str = str.replaceFirst("\"", "");
			return str.substring(0, str.length()-1);
		}
		return str;
	}
	
	
	/**
	 * Returns a quoted String (double quote)·
	 * @param str  input string
	 * @return quoted input string
	 */
	public static String quote(String str) {
		return "\"" + str + "\"";
	}
	
	public static String singleQuote(String str) {
		return "\'" + str + "\'";
	}
	
	public static String escapeQuotes(String str) {
		return str.replaceAll("\\\"", "\\\\\"").replaceAll("\\\'", "\\\\\'");
	}
	
	/**
	 * Checks whether a given value is a constant.
	 * Here a constant is a quoted value.
	 * @param val
	 * @return true if val is a constant, false otherwise
	 */
	public static boolean isConstant(String val) {
		return val.startsWith("\"") && val.endsWith("\"");
	}
	
	
	public static String millisecondsToFormattedTime(long milliseconds) {
		final String SEP = ", ";
		int millis  = (int) milliseconds % 1000; 
		int seconds = (int) (milliseconds / 1000) % 60 ;
		int minutes = (int) ((milliseconds / (1000*60)) % 60);
		int hours   = (int) ((milliseconds / (1000*60*60)) % 24);
		
		StringBuilder sb = new StringBuilder();
		sb.append(hours > 0? hours + " hours" + SEP : "");
		sb.append(minutes > 0? minutes + " min" + SEP : "");
		sb.append(seconds > 0? seconds + " sec" + SEP : "");
		sb.append(millis >= 0? millis + " ms" : "");
		return sb.toString();
	}
	
	public static String humanReadableByteCount(long bytes, boolean si) {
	    int unit = si ? 1000 : 1024;
	    if (bytes < unit) return bytes + " B";
	    int exp = (int) (Math.log(bytes) / Math.log(unit));
	    String pre = (si ? "kMGTPE" : "KMGTPE").charAt(exp-1) + (si ? "" : "i");
	    return String.format("%.1f %sB", bytes / Math.pow(unit, exp), pre);
	}
	
	
	
	/**
	 * List join function, which creates a single string of the items of the 
	 * array separated by _sep. If "spaceFirst" is set to true the first two elements
	 * are joined by a space character.
	 * @param list   the input list
	 * @param _sep
	 * @param spaceFirst
	 * @returns a single assembled string
	 */
	public static <T> String join(List<T> list, String _sep, Boolean spaceFirst) {
	    String sep = "";
	    StringBuilder result = new StringBuilder();
	    for (int i = 0; i < list.size(); i++) {
	    	if (!list.get(i).toString().isEmpty())
	    		result.append(sep + list.get(i).toString());
	        sep = (i == 0 && spaceFirst)? " " : _sep;
	    }   
	    return result.toString();
	}

	public static <T> String join(List<T> list, String _sep) {
	    return join(list, _sep, false);
	}

	public static <T> String join(List<T> list) {
	    return join(list, "");
	}

	
	/**
	 * Recursively searches a given directory for certain file types
	 * @param dir  the directory file
	 * @param extensions  an array of file extensions without leading dot
	 * @return a list of {@link File}s
	 */
	public static List<File> collectFiles(File dir, String[] extensions) {
		ArrayList<File> files = new ArrayList<File>();

		// gather all input files
		if (dir.isDirectory()) {
		    try {
		         // Finds files within a root directory and optionally its·
		         // subdirectories which match an array of extensions.
		         // This method will returns matched file as java.io.File
		         boolean recursive = true;

		         Collection<File> foundFiles = FileUtils.listFiles(dir, extensions, recursive);

		         for (Iterator<File> iterator = foundFiles.iterator(); iterator.hasNext();) {
		             files.add(iterator.next());
		         }   
		     } catch (Exception e) {
		         //e.printStackTrace();
		     }   
		}

		return files;
	}
	
	
	public interface IPredicate<T> { boolean apply(T type); }
	
	public static <T> Collection<T> filter(Collection<T> target, IPredicate<T> predicate) {
	    Collection<T> result = new ArrayList<T>();
	    for (T element: target) {
	        if (predicate.apply(element)) {
	            result.add(element);
	        }
	    }
	    return result;
	}
	
	public static <T> Collection<T> filter(T[] target, IPredicate<T> predicate) {
		return filter(Arrays.asList(target), predicate);
	}

	
	
	/**
	 * Serialize an Java Object to disk
	 * @param targetFile the {@link File} to store the object
	 * @param obj  a serializable {@link Object}
	 * @return true if no exception was thrown, false otherwise
	 * @throws IOException
	 */
	public static boolean object2Disk(final File targetFile, final Object obj) {
		File basePath = new File(targetFile.getPath().substring(0, targetFile.getPath().lastIndexOf(File.separator)));
		if (!basePath.exists()) basePath.mkdirs();
		
		try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(targetFile))) {
			oos.writeObject(obj);
		} catch (IOException e) {
			//logger.warn(Utils.stacktrace2Str(e));
			return false;
		}

		return true;
	}


	/**
	 * Deserialize a Java Object from disk
	 * @param file the {@link File} to read the object from
	 * @return the deserialized {@link Object} 
	 * @throws ClassNotFoundException 
	 */
	public static Object disk2Object(File file) throws ClassNotFoundException {
		Object obj = null;
		
		try (ObjectInputStream in = new ObjectInputStream(new FileInputStream(file))) {
			obj = in.readObject();
		} catch (IOException e) {
			//logger.warn(Utils.stacktrace2Str(e));
		}
		
		return obj;
	}


	/**
	 * Export app statistics to a JSON file
	 * @param jsonFile  the Json {@link File} to store the results
	 * @param stats  the {@link AppStats} object
	 * @throws IOException
	 */
    public static void obj2JsonFile(File jsonFile, AppStats stats) throws IOException {
		File basePath = new File(jsonFile.getPath().substring(0, jsonFile.getPath().lastIndexOf(File.separator)));
		if (!basePath.exists()) basePath.mkdirs();
		
		GsonBuilder builder = new GsonBuilder();
		Gson gson = builder.create();
		String jsonOut = gson.toJson(new SerializableAppStats(stats));
		
		try (FileOutputStream fos = new FileOutputStream(jsonFile)) {
			fos.write(jsonOut.getBytes());
		} catch (IOException e) {
			//logger.warn(Utils.stacktrace2Str(e));
		}
    }


	public static void obj2JsonFile(File jsonFile, Object obj) throws IOException {
		File basePath = new File(jsonFile.getPath().substring(0, jsonFile.getPath().lastIndexOf(File.separator)));
		if (!basePath.exists()) basePath.mkdirs();

		GsonBuilder builder = new GsonBuilder();
		Gson gson = builder.create();
		String jsonOut = gson.toJson(obj);

		try (FileOutputStream fos = new FileOutputStream(jsonFile)) {
			fos.write(jsonOut.getBytes());
		} catch (IOException e) {
			//logger.warn(Utils.stacktrace2Str(e));
		}
	}




	public static String stacktrace2Str(Throwable t) {
		StringWriter sw = new StringWriter();
		t.printStackTrace(new PrintWriter(sw));
		return sw.toString(); // stack trace as a string
	}
}
