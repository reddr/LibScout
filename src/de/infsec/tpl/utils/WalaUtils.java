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

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ibm.wala.classLoader.CallSiteReference;
import com.ibm.wala.classLoader.IClass;
import com.ibm.wala.classLoader.IMethod;
import com.ibm.wala.ipa.callgraph.CGNode;
import com.ibm.wala.ipa.callgraph.CallGraph;
import com.ibm.wala.ipa.callgraph.propagation.InstanceKey;
import com.ibm.wala.ipa.callgraph.propagation.PointerAnalysis;
import com.ibm.wala.ipa.callgraph.propagation.PointerKey;
import com.ibm.wala.ipa.cha.IClassHierarchy;
import com.ibm.wala.shrikeBT.ConditionalBranchInstruction;
import com.ibm.wala.shrikeBT.IComparisonInstruction;
import com.ibm.wala.ssa.IR;
import com.ibm.wala.ssa.SSACFG;
import com.ibm.wala.ssa.SSAInvokeInstruction;
import com.ibm.wala.ssa.SSACFG.BasicBlock;
import com.ibm.wala.ssa.SSAInstruction;
import com.ibm.wala.types.ClassLoaderReference;import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import com.ibm.wala.types.Descriptor;
import com.ibm.wala.types.MethodReference;
import com.ibm.wala.types.TypeReference;
import com.ibm.wala.util.intset.OrdinalSet;

import de.infsec.tpl.exceptions.MethodNotFoundException;
import de.infsec.tpl.utils.AndroidClassType;
import de.infsec.tpl.utils.AndroidEntryPointConstants;
import de.infsec.tpl.utils.Utils.IPredicate;



/**
 * Utility functions that facilitate the work with the WALA framework
 * @author Erik Derr
 *
 */
public class WalaUtils {
	private static final Logger logger = LoggerFactory.getLogger(de.infsec.tpl.utils.WalaUtils.class);

	public static final String WALA_FAKE_ROOT_CLASS = "com.ibm.wala.FakeRootClass";
	public static final String WALA_FAKE_ROOT_METHOD_SIGNATURE = WALA_FAKE_ROOT_CLASS + ".fakeRootMethod()V";
	public static final String WALA_FAKE_WORLD_CLINIT_SIGNATURE = WALA_FAKE_ROOT_CLASS + ".fakeWorldClinit()V";

	// TIP:  use vm argument -Dwala.dump.ssa to dump Wala IR
	
	/*
	 * Example invoke instruction:
	 * ------------------------------
	 * 25 = invokevirtual < Application, Landroid/content/Intent, putExtra(Ljava/lang/String;Landroid/os/Parcelable;)Landroid/content/Intent; > 20,22,23 @50 exception:24
	 * ------------------------------
     * defs: 25,24
     * uses: 20,22,23
     * pc  : 50
	 */ 
	
	
    public static String simpleName(IClass c) {
    	return c == null? "null" : Utils.convertToFullClassName(c.getName().toString());
    }
	
	public static IPredicate<SSAInstruction> invokeFilter = new Utils.IPredicate<SSAInstruction>() {
		@Override
		public boolean apply(SSAInstruction type) {
			return type instanceof SSAInvokeInstruction;
		}
	};

	
	/**
	 * Looks up a method by name in a class object. If the method is overloaded,
	 * the first one found is returned.
	 * @param clazz  IClass object
	 * @param methodName name of the method to be looked up
	 * @return IMethod if method is declared in clazz, null otherwise
	 */
	public static IMethod getMethodByName(IClass clazz, String methodName) {
		for (IMethod m: clazz.getAllMethods()) { // DeclaredMethods()) -> only impl./overriden methods
			if (m.getSelector().toString().startsWith(methodName)) {
				return m;
			}
		}
		return null;
	}
	
	
	public static boolean declaresMethodByName(IClass clazz, String methodName) {
		return getMethodByName(clazz, methodName) == null? false : true; 
	}
	
	
	
	

	/**
	 * Hierarchy lookup of a method selector. If the method is not declared in the class
	 * the lookup is continued at the superclass. This is continued until the method is found or
	 * the Object class is reached
	 * @param clazz   the IClass to start with
	 * @param selector  the method selector
	 * @return  a IMethod object of the method in question
	 * @throws MethodNotFoundException
	 */
	public static IMethod lookupMethod(IClass clazz, String selector) throws MethodNotFoundException {
		for (IMethod im: clazz.getAllMethods()) {
			if (im.getSelector().toString().equals(selector)) {
				return im;
			}
		}
		throw new MethodNotFoundException("[lookupMethod] Method " + selector + " not found in class: " + clazz.getName().toString() + " and its superclasses");
	}
	
	
	/**
	 * Checks whether some instruction is both an {@link com.ibm.wala.ssa.SSAInvokeInstruction} and if its signature
	 * matches a given signature
	 * @param ins  an {@link com.ibm.wala.ssa.SSAInstruction}
	 * @param methodSignature a method signature to check against
	 * @return
	 */
	public static boolean checkMethodSignature(final SSAInstruction ins, final String methodSignature) {
		if (ins instanceof SSAInvokeInstruction) {
			final SSAInvokeInstruction inv = (SSAInvokeInstruction) ins;
			return inv.getDeclaredTarget().getSignature().equals(methodSignature);
		}
		return false;
	}
	
	
	/**
	 * Collects all implemented interfaces for a given class
	 * @param clazz  the IClass object to analyze
	 * @return a set of IClass objects representing the interfaces
	 */
	public static Set<IClass> collectAllInterfaces(IClass clazz) {
		// do not check array classes
		if (clazz.isArrayClass()) return new HashSet<IClass>();
		
		Set<IClass> interfaces = new HashSet<IClass>(clazz.getDirectInterfaces());
		for (IClass c : clazz.getDirectInterfaces())
			interfaces.addAll(collectAllInterfaces(c));
	
		return interfaces;
	}
	

	/**
	 * Looks up an IClass for a given class name
	 * @param cha  a {@link IClassHierarchy}
	 * @param clazzName  in java notation, e.g. "de.infsec.MyActivity"
	 * @return a {@link IClass} object
	 * @throws ClassNotFoundException
	 */
	public static IClass lookupClass(IClassHierarchy cha, String clazzName) throws ClassNotFoundException {
		if (clazzName == null)
			throw new ClassNotFoundException(Utils.INDENT + "class name is NULL");
		
		String convertedClass = Utils.convertToBrokenDexBytecodeNotation(clazzName);
		IClass iclazz = cha.lookupClass(TypeReference.findOrCreate(ClassLoaderReference.Application, convertedClass));
		
		if (iclazz == null)
			throw new ClassNotFoundException(Utils.INDENT + "[lookupClass] Could'nt lookup IClass for " + clazzName);
		
		return iclazz;
	}
	
	
	@Deprecated
	public static boolean isApplicationClass(IClass clazz) {
		// we need the additional check as framework classes from the support package are loaded via the Application classloader
		return clazz.getClassHierarchy().getScope().isApplicationLoader(clazz.getClassLoader())
				&& !clazz.getName().toString().startsWith("Landroid");  // strip android.v4 / android.v7 support packages as they are considered part of the framework // TODO necessary? support packages are loaded via Primordial!
	}
	
	
	public static boolean isAppClass(IClass clazz) {
		// filter empty dummy classes
		// possibly related too: http://bugs.java.com/bugdatabase/view_bug.do?bug_id=4295934
		boolean isEmptyInnerClass = WalaUtils.isInnerClass(clazz)
									&& isAnonymousInnerClass(clazz)
									&& (clazz.getDeclaredMethods().isEmpty() || 
									   (clazz.getDeclaredMethods().size() == 1 && clazz.getDeclaredMethods().iterator().next().isClinit())
									&& clazz.getDeclaredInstanceFields().isEmpty()
									&& clazz.getDeclaredStaticFields().isEmpty()
									&& clazz.getDirectInterfaces().isEmpty());

		
		return clazz.getClassHierarchy().getScope().isApplicationLoader(clazz.getClassLoader()) && !isAndroidResourceClass(clazz) && !isEmptyInnerClass;
	}
	
	public static boolean isExtensionClass(IClass clazz) {
		return clazz.getClassLoader().getReference().equals(clazz.getClassHierarchy().getScope().getExtensionLoader());
	}
	
	
    /**
     * @param clazz IClass
     * @return
     */
    public static boolean isAnonymousInnerClass(final String clazzName) {
        final Pattern anonymusInnerClassPattern = Pattern.compile("^.+\\$[0-9]+\\..+$");
        final Matcher matcher = anonymusInnerClassPattern.matcher(clazzName);

        return matcher.matches();
    }

	
	public static boolean isAnonymousInnerClass(final IClass clazz) {
        return isAnonymousInnerClass(simpleName(clazz));
    }
	
	/**
	 * Retrieves all superclasses for a given class including itself
	 * @param clazz  the input IClass object
	 * @return  a list of IClass superclass objects including the input class
	 */
	public static List<IClass> getSuperClassesIncluding(IClass clazz) {
		LinkedList<IClass> superclasses = new LinkedList<IClass>(getSuperClasses(clazz));
		superclasses.addFirst(clazz);
		
		return superclasses;
	}

	
	/**
	 * Retrieves all superclasses for a given class
	 * @param clazz  the input IClass object
	 * @return  a list of IClass superclass objects or an empty list if there is no superclass
	 */
	public static List<IClass> getSuperClasses(IClass clazz) {
		ArrayList<IClass> superclasses = new ArrayList<IClass>();

		while (clazz.getSuperclass() != null) {  
			clazz = clazz.getSuperclass();
			superclasses.add(clazz);
		}
		
		return superclasses;
	}
	
	

	public static IMethod getIMethod(IClassHierarchy cha, String signature) {  // TODO: throw exceptions
		String clazzName = Utils.getFullClassName(signature);
		String selector = signature.substring(clazzName.length()+1); 

		try {
			IClass clazz = WalaUtils.lookupClass(cha, clazzName);
			for (IMethod m: clazz.getAllMethods()) { // DeclaredMethods()) -> only impl./overriden methods
				if (m.getSelector().toString().equals(selector)) {
					return m;
				}
			}
		} catch (ClassNotFoundException e) {
			logger.debug("Classname " + clazzName + " could not be looked up!");
		}
		return null;  // TODO: throw exception
	}

	
	
	public static IR getIR(IMethod method, CallGraph cg) {
		CGNode node = getCGNode(method, cg); 
		return node == null? null : node.getIR();
	}
	
	public static CGNode getCGNode(IMethod method, CallGraph cg) {
		logger.debug("Retrieve CGNode for " + method.getSignature());

		MethodReference ref = method.getReference();
		if (ref == null) return null;

		Set<CGNode> cgnode = cg.getNodes(ref);
		if (cgnode.isEmpty()) {
			logger.warn("Number of CGNode(s) for " + method.getSignature() + " is " + cgnode.size());
			return null;
		}
		/*else if (cgnode.size() > 1) {
			logger.warn("Number of CGNode(s) for " + methodSignature + " is " + cgnode.size() +  "  refMethod.sig: " + refMethod.getSignature());
		}*/
						
		return cgnode.iterator().next();
	}

	
	public static CGNode getCGNode(String methodSignature, CallGraph cg) {
		logger.debug("Retrieve CGNode for " + methodSignature);

		IMethod refMethod = getIMethod(cg.getClassHierarchy(), methodSignature);
		if (refMethod == null) return null;

		return getCGNode(refMethod, cg);
	}

		
	public static IR getIR(String methodSignature, CallGraph cg) {
		CGNode node = getCGNode(methodSignature, cg); 
		return node == null? null : node.getIR();
	}
	
	
	public static SSACFG getSSACFG(String methodSignature, CallGraph cg) {
		logger.debug("Retrieve SSACFG for " + methodSignature);

		IR ir = getIR(methodSignature, cg);
		if (ir == null && !methodSignature.startsWith(WALA_FAKE_ROOT_CLASS))
			logger.warn("Could not retrieve IR for " + methodSignature);		
		
		return ir == null? null : ir.getControlFlowGraph();
	}

	
	
	public static SSAInstruction getSSAInstruction(CallGraph cg, String methodSignature, int iindex) {
		SSACFG cfg = getSSACFG(methodSignature, cg);
		if (cfg == null) {
			logger.warn("getSSAInstruction:: Did not find SSACFG for " + methodSignature);			
		} else {
			BasicBlock block = cfg.getBlockForInstruction(iindex);
			if (block != null) {
				for (Iterator<SSAInstruction> it = block.iterateNormalInstructions(); it.hasNext();) {
					SSAInstruction ins = it.next();
					if (ins.iindex == iindex) {
						return ins;
					}
				}
				logger.warn("getSSAInstruction:: Did not find iindex " + iindex + " in SSACFG (" + methodSignature + ")");
			} else
				logger.warn("getSSAInstruction:: Did not find basic block for iindex " + iindex + " in SSACFG (" + methodSignature + ")");
		}
		return null;
	}
	
	
	
	
	public static String getClassName(IClass clazz) {
		// Strip package name
		String clazzName = clazz.getName().toString().substring(clazz.getName().toString().lastIndexOf("/")+1); 
		return clazzName.endsWith(";")? clazzName.substring(0, clazzName.length()-1) : clazzName;
	}
	
	public static boolean isInnerClassOf(IClass clazz, IClass testClazz) {
		// TODO: innerclass check would be easier if the dex bytecode annotations would have been parsed!
		//       here we have to fallback to the potentially non-reliable name check
		String clazzName = getClassName(clazz);
		String testClazzName = getClassName(testClazz);
		
		return testClazzName.contains("$") && testClazzName.startsWith(clazzName);
	}

	public static boolean isInnerClass(IClass clazz) {
		// TODO: innerclass check would be easier if the dex bytecode annotations would have been parsed!
		//       here we have to fallback to the potentially non-reliable name check
		return getClassName(clazz).contains("$");
	}

	public static boolean isAndroidResourceClass(IClass clazz) {
		// match R and BuildConfig class and their inner classes
		String clazzName = getClassName(clazz);
		return clazzName.equals("R") || clazzName.startsWith("R$") || clazzName.equals("BuildConfig");

	}
	
	
	
	// Strangely there is no such function in IClass
	public static boolean isFinal(IClass clazz) {
		return (clazz.getModifiers() & 0x0010) != 0;
	}

	
	public static String op2str(ConditionalBranchInstruction.IOperator op) {
        if (op instanceof ConditionalBranchInstruction.Operator) {
            switch ((ConditionalBranchInstruction.Operator) op) {
                case EQ:
                    return "==";
                case GE:
                    return ">=";
                case GT:
                    return ">";
                case LE:
                    return "<=";
                case LT:
                    return "<";
                case NE:
                    return "!=";
            }
        }

        return "?";
    }

    public static String op2str(IComparisonInstruction.Operator opcode) {
        switch (opcode) {
            case CMP:
                return "==";
            case CMPG:
                return ">";
            case CMPL:
                return "<";
        }

        return opcode.name();
    }
    
    
	public static AndroidClassType classifyClazz(IClassHierarchy cha, String clazzName) throws ClassNotFoundException {
		IClass ic = lookupClass(cha, clazzName);
		return classifyClazz(ic);
	}
	
	/**
	 * Checks whether a given class is one of Android's main class types (Activity, Service, ..)
	 * @param clazz  The IClass object to check
	 * @return  an AndroidClassType object
	 */
	public static AndroidClassType classifyClazz(IClass clazz) {
		for (IClass c: WalaUtils.getSuperClassesIncluding(clazz)) {
			
			if (WalaUtils.simpleName(c).equals(AndroidEntryPointConstants.ACTIVITYCLASS))
				return AndroidClassType.Activity;
			
			else if (WalaUtils.simpleName(c).equals(AndroidEntryPointConstants.FRAGMENTCLASS) ||
					 WalaUtils.simpleName(c).equals(AndroidEntryPointConstants.SUPPORTFRAGMENTCLASS))   // Apps that support API level < 11 have to use the support.v4 version
				return AndroidClassType.Fragment;
			
			else if (WalaUtils.simpleName(c).equals(AndroidEntryPointConstants.SERVICECLASS))
				return AndroidClassType.Service;

			else if (WalaUtils.simpleName(c).equals(AndroidEntryPointConstants.BROADCASTRECEIVERCLASS))
				return AndroidClassType.BroadcastReceiver;
			
			else if (WalaUtils.simpleName(c).equals(AndroidEntryPointConstants.CONTENTPROVIDERCLASS))
				return AndroidClassType.ContentProvider;
			
			else if (WalaUtils.simpleName(c).equals(AndroidEntryPointConstants.APPLICATIONCLASS))
				return AndroidClassType.Application;
			
			else if (WalaUtils.simpleName(c).equals(AndroidEntryPointConstants.ASYNCTASKCLASS))
				return AndroidClassType.AsyncTask;

			else if (WalaUtils.simpleName(c).equals(AndroidEntryPointConstants.THREADCLASS))
				return AndroidClassType.Thread;
			
			else if (WalaUtils.simpleName(c).equals(AndroidEntryPointConstants.HANDLERCLASS))
				return AndroidClassType.Handler;
			
			else if (WalaUtils.simpleName(c).equals(AndroidEntryPointConstants.VIEWGROUP_TYPE))
				return AndroidClassType.LayoutContainer;
			
			// technically webview is a viewgroup, however in practice it is used as an atomic view
			else if (WalaUtils.simpleName(c).equals(AndroidEntryPointConstants.VIEW_TYPE) ||
					 WalaUtils.simpleName(c).equals(AndroidEntryPointConstants.WEBVIEW_TYPE))
				return AndroidClassType.View;
		}

		return AndroidClassType.Plain;
	}
}
