package de.infsec.tpl.modules.libapi;


import com.ibm.wala.classLoader.IClass;
import com.ibm.wala.classLoader.IMethod;
import com.ibm.wala.ipa.cha.IClassHierarchy;
import de.infsec.tpl.hash.AccessFlags;
import de.infsec.tpl.pkg.PackageUtils;
import de.infsec.tpl.utils.Utils;
import de.infsec.tpl.utils.WalaUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;
import java.util.stream.Collectors;


/**
 *  Extracts the public API and documented public API (to be used by client) from a library.jar
 *  Filters ProGuard obfuscated methods/classes (identifier renaming)
 *
 *  Related info:
 *    - http://wiki.eclipse.org/Evolving_Java-based_APIs
 *    -> javadoc parsing for pre-/post-condition changes in same APIs (aka semantic changes)
 *
 */
public class PublicInterfaceExtractor {
    private static final Logger logger = LoggerFactory.getLogger(de.infsec.tpl.modules.libapi.PublicInterfaceExtractor.class);


    public static Set<IMethod> getPublicInterface(IClassHierarchy cha) {
        int classCount = 0;   // how many distinct classes have public methods
        HashSet<IMethod> pubMethods = new HashSet<IMethod>();

        for (IClass clazz: cha) {
            if (!WalaUtils.isAppClass(clazz)) continue;

            Collection<? extends IMethod> methods = clazz.getDeclaredMethods();

            // filter anything but public and non-compiler generated methods
            methods = methods.stream()
                    .filter(m -> {
                        int code = AccessFlags.getMethodAccessCode(m);
                        return code > 0 && (code & AccessFlags.getPublicOnlyFilter()) == 0x0;
                    })  // if predicate is true, keep in list
                    .filter(m -> !(m.isBridge() || m.isSynthetic()))   // filter compiler-generated methods
                    .collect(Collectors.toCollection(ArrayList::new));

            if (!methods.isEmpty()) classCount++;
            pubMethods.addAll(methods);
        }

        logger.debug("[getPublicInterface] Retrieved " + pubMethods.size() + " public methods from " + classCount + " distinct classes");
        return pubMethods;
    }


    /**
     * Try to programmatically infer the documented public library interface, i.e., the public methods
     * that the app developer is supposed to use.
     * This filter obfuscated names (id-renaming via ProGuard), public method of anonymous inner-classes and
     * public methods in internal packages (based on keywords)
     * @param cha
     * @return
     */
    public static Set<IMethod> getDocumentedPublicInterface(IClassHierarchy cha) {
        Set<IMethod> methods = getPublicInterface(cha);
        int pubApiCount = methods.size();

        methods = methods.stream()
                .filter(m -> !WalaUtils.isAnonymousInnerClass(m.getDeclaringClass()))  // filter pub methods in anonymous inner classes
                .filter(m -> !isSignatureRenamed(m))   // filter obfuscated names
                .filter(m -> !isLibInternalMethod(m))  // is lib internal based on keywords
                .collect(Collectors.toCollection(HashSet::new));

        ArrayList<IMethod> list = new ArrayList<IMethod>(methods);
        list.sort(Comparator.comparing(IMethod::getSignature));


//        list.forEach(m -> logger.debug(Utils.INDENT + "[DocAPI] " + m.getSignature() + (m.getDeclaringClass().isInterface()? "   [IS_IF_METHOD] " : "  ")));
        logger.debug("[getDocumentedPublicInterface] Retrieved " + list.size() + " doc public APIs  (filtered: " + (pubApiCount-list.size()) + " public APIs)");


        // TODO: entrypoint analysis with code?
        // filter other? find lib entry points (calls within the lib?)
        // -> if pub method is never called, likely to be doc api  (or thread->start -> run)

        return methods;
    }



    /**
     * Check if package name includes a subpackage named 'internal'
     * @param m
     * @return
     */
    private static boolean isLibInternalMethod(IMethod m) {
        // check a part of the package contains 'internal'
        List<String> pckgFragments = PackageUtils.parsePackage(m.getDeclaringClass());

        for (String frag: pckgFragments) {
            if ("internal".equals(frag)) {
                return true;
            }
        }

        return false;
    }



    private static boolean isSignatureRenamed(IMethod m) {
        logger.trace(Utils.INDENT2 + "- Check for renaming: " + m.getSignature());

        // check if method name has been renamed
        boolean renamed = isIdentifierRenamed(m.getReference().getName().toString());
        if (renamed) {
            logger.trace(Utils.indent(3) + "-> method name " + m.getReference().getName().toString() + " is renamed");
            return true;
        }

        // check whether the class name has been renamed (e.g. when method is something like <[cl]init> or toString()
        // in case we have (a) named inner-class(es), we check whether all classes were renamed
        List<String> clazz = new ArrayList<String>();
        String[] cz = WalaUtils.getClassName(m.getDeclaringClass()).split("\\$");
        clazz.addAll(Arrays.asList(cz));

        renamed = false;
        for (String c: clazz) {
            renamed = isIdentifierRenamed(c);
        }
        if (renamed) {
            logger.trace(Utils.indent(3) + "-> class name " + WalaUtils.getClassName(m.getDeclaringClass()) + " is renamed");
            return true;
        }


        // TODO: probably not necessary (unlikely that method/class is not renamed but packagename
        // check whether a subset of the package name has been renamed
        renamed = false;
        List<String> pckgFragments = PackageUtils.parsePackage(m.getDeclaringClass());
        // logger.debug("      pckg fragments: " + Utils.join(pckgFragments, ","));

        for (String frag: pckgFragments) {
            boolean fragRenamed = isIdentifierRenamed(frag);
            // logger.debug("          frag " + frag + "  renamed: " + fragRenamed   +  "   currentRenamed: " + renamed);

            if (renamed && !fragRenamed)
                // non-obfuscated package fragments must not follow obfuscated ones
                return false;

            renamed = fragRenamed;
        }

        return renamed;
    }



    /**
     *  filter proguard-obfuscated methods and subpackage identifier
     * (created with its SimpleNameFactory and SpecialNameFactory)
     *
     * Limit detection to 2-char names to avoid false positives (non-obfuscated method names such as "foo")
     *   For mixedCaseNames this is 56^2 = 2704 combinations (e.g. aR, Bm, mB,..)
     *   For lowerCaseNames this is 26^2 =  676 combinations (e.g. aa, cd, ea,..)
     * The number of combinations is per-package. Default Android Studio settings are lowercase only.
     * In addition, ProGuard might append an underscore '_' to resolve ambiguous names (that were created during obfuscation)
     */
    private static boolean isIdentifierRenamed(String str) {
        if (str.length() == 3 && str.charAt(2) == '_')
            str = str.substring(0,1);  // strip underscore

        if (str.length() == 1 || str.length() == 2) {
            return str.matches("[a-zA-Z]{1,2}");
        }

        return false;
    }

}
