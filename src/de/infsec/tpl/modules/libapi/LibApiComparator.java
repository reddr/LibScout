package de.infsec.tpl.modules.libapi;

import com.github.zafarkhaja.semver.Version;
import com.ibm.wala.classLoader.IClass;
import com.ibm.wala.classLoader.IMethod;
import de.infsec.tpl.stats.Exportable;
import de.infsec.tpl.utils.Utils;
import de.infsec.tpl.utils.VersionWrapper;
import de.infsec.tpl.utils.WalaUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.rmi.CORBA.Util;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Feature: Tests the relationship/compatibility of documented API sets of consecutive versions
 */
public class LibApiComparator {
    private static final Logger logger = LoggerFactory.getLogger(LibApiComparator.class);
    private Map<Version, ApiDiff> version2ApiDiff;


    /**
     * API Diff Statistics compared to predecessor version
     */
    class ApiDiff implements Exportable {
        Version v;
        int apiCount;
        VersionWrapper.SEMVER expectedSemver = null;
        VersionWrapper.SEMVER actualSemver = null;
        Set<IMethod> removed = new HashSet<IMethod>();
        Set<IMethod> added = new HashSet<IMethod>();
        Map<IMethod, Set<IMethod>> alternatives = new HashMap<IMethod, Set<IMethod>>();

        ApiDiff(Version v, int apiCount) {
            this.v = v;
            this.apiCount = apiCount;
        }

        public void print(boolean verbose) {
            boolean diff = false;
            boolean critical = false;
            if (expectedSemver != null) {
                diff = !expectedSemver.equals(actualSemver);
                critical =  (expectedSemver.equals(VersionWrapper.SEMVER.PATCH) || expectedSemver.equals(VersionWrapper.SEMVER.MINOR)) &&
                        actualSemver.equals(VersionWrapper.SEMVER.MAJOR);
            }

            // version, #docAPI, apiCountDiff expSemver,  actSemver,  diff?,  critical?
            logger.info(String.format("%10s %10d %-15s  %8s %8s %10s %15s",
                    v.toString(),
                    apiCount,
                    added.size() > 0 || removed.size() > 0? "  (+" + added.size() + "/-" + removed.size() + ")" : "",
                    expectedSemver != null? expectedSemver.toString() : "---",
                    actualSemver != null? actualSemver.toString() : "---",
                    diff? "[DIFF]" : "",
                    critical? "[CRITICAL]" : ""));

            if (verbose) {
                final int LIMIT = 15;  // print max number of methods
                removed.stream().map(IMethod::getSignature).sorted().limit(LIMIT).forEach(m -> logger.info(Utils.INDENT2 + "- removed: " + m));
                for (IMethod m: alternatives.keySet()) {
                    logger.info(Utils.INDENT2 + "Alternatives for " + m.getSignature());
                    alternatives.get(m).stream().map(IMethod::getSignature).sorted().forEach(s -> logger.info(Utils.indent(3) + "> alt: " + s));
                }
                added.stream().map(IMethod::getSignature).sorted().limit(LIMIT).forEach(m -> logger.info(Utils.INDENT2 + "+   added: " + m));
            }
        }

        @Override
        public Export export() {
            return new Export(this);
        }


        public class Export {
            String version;
            int apiCount;
            int apiAdditionsCount;
            int apiDeletionsCount;
            Set<String> apiAdditions = new TreeSet<String>();
            Set<String> apiDeletions = new TreeSet<String>();
            String expectedSemver;
            String actualSemver;
            Map<String, Set<String>> alternatives = new TreeMap<String, Set<String>>();

            public Export(ApiDiff diff, boolean verbose) {
                version = diff.v.toString();
                apiCount = diff.apiCount;
                apiAdditionsCount = diff.added.size();
                apiDeletionsCount = diff.removed.size();
                actualSemver = diff.actualSemver == null? "" : diff.actualSemver.name();
                expectedSemver = diff.expectedSemver == null? "" : diff.expectedSemver.name();

                for (IMethod m: diff.alternatives.keySet()) {
                    Set<String> apis = diff.alternatives.get(m).stream().map(IMethod::getSignature).collect(Collectors.toSet());
                    alternatives.put(m.getSignature(), apis);
                }

                if (verbose) {
                    apiAdditions = diff.added.stream().map(IMethod::getSignature).sorted().collect(Collectors.toSet());
                    apiDeletions = diff.removed.stream().map(IMethod::getSignature).sorted().collect(Collectors.toSet());
                }
            }

            public Export(ApiDiff diff) {
                this(diff, false);
            }
        }
    }



    // need to infer expected and actual semver
    protected Map<Version, ApiDiff> run(LibApiStats stats) {

        version2ApiDiff = new TreeMap<Version, ApiDiff>();
        Map<Version, Set<IMethod>> version2Api =  generatePerVersionApiSet(stats);

        for (Version v: version2Api.keySet()) {
            version2ApiDiff.put(v, new ApiDiff(v, version2Api.get(v).size()));
        }

        // infer expected/actual semver
        inferExpectedSemver();
        inferActualSemver(version2Api);
        inferAlternativeAPIs(version2Api);

//        if (logger.isDebugEnabled()) {
        logger.info("======================================");
        logger.info("==  Library: " + stats.libName + "  ==");
        logger.info("======================================");
        printStats();
  //      }

        return version2ApiDiff;
    }


    private void printStats() {
        logger.info(String.format("%10s %10s %-15s %10s %10s %10s %15s",
                "Version", "#docAPI", "  apiDiff", "expSemver",  "actSemver", "   diff?  ", "  critical?  "));
        logger.info("---------------------------------------------------------------------------------------------");

        for (Version v: version2ApiDiff.keySet()) {
            version2ApiDiff.get(v).print(false);//true);//false);
        }
        logger.info("---------------------------------------------------------------------------------------------");
    }


    void inferExpectedSemver() {
        Iterator<Version> it = version2ApiDiff.keySet().iterator();
        Version old = it.next();

        while (it.hasNext()) {
            Version cur = it.next();
            VersionWrapper.SEMVER sem = VersionWrapper.getExpectedSemver(old,cur);
            version2ApiDiff.get(cur).expectedSemver = sem;

            logger.debug(Utils.INDENT2 + "Expected SemVer:: " + old.toString() + " : " + cur.toString() + "  ->  " + sem.name());
            old = cur;
        }
    }


    Map<Version, Set<IMethod>> generatePerVersionApiSet(LibApiStats stats) {
        Map<Version, Set<IMethod>> version2Api = new TreeMap<Version, Set<IMethod>>();

        for (String v: stats.versions) {
            Set<IMethod> apis = new HashSet<IMethod>();

            for (IMethod api: stats.api2Versions.keySet()) {
                if (stats.api2Versions.get(api).contains(v))
                    apis.add(api);
            }

            version2Api.put(VersionWrapper.valueOf(v), apis);
        }

        return version2Api;
    }


    void inferActualSemver(Map<Version, Set<IMethod>> version2Api) {
        Iterator<Version> it = version2ApiDiff.keySet().iterator();
        Version v0 = it.next();

        while (it.hasNext()) {
            Version v1 = it.next();
            VersionWrapper.SEMVER sem = compareApis(version2Api.get(v0), version2Api.get(v1));
            version2ApiDiff.get(v1).actualSemver = sem;

            // determine added/removed APIs
            if (!sem.equals(VersionWrapper.SEMVER.PATCH)) {
                Set<IMethod> removed = new HashSet<IMethod>(version2Api.get(v0));
                removed.removeAll(version2Api.get(v1));
                version2ApiDiff.get(v1).removed = removed;

                Set<IMethod> added = new HashSet<IMethod>(version2Api.get(v1));
                added.removeAll(version2Api.get(v0));
                version2ApiDiff.get(v1).added = added;
            }

            logger.debug(Utils.INDENT2 + "Actual SemVer:: " + v0.toString() + " : " + v1.toString() + "  ->  " + sem.name());
            v0 = v1;
        }
    }


    /*
     * Check for each version with actual semver = major for each removed
     * API for alternative APIs
     */
    void inferAlternativeAPIs(Map<Version, Set<IMethod>> version2Api) {
        for (Version v: version2ApiDiff.keySet()) {
            ApiDiff diff = version2ApiDiff.get(v);

            if (diff.actualSemver != null && diff.actualSemver.equals(VersionWrapper.SEMVER.MAJOR)) {
                for (IMethod m: diff.removed) {
                    Set<IMethod> alternatives = checkForAlternatives(m, diff.removed, version2Api.get(v));

                    if (!alternatives.isEmpty())
                        diff.alternatives.put(m, alternatives);
                }
            }
        }
    }


    static Set<IMethod> checkForAlternatives(IMethod removedApi, Set<IMethod> removedAPIs, Set<IMethod> docAPIs) {
        Set<IMethod> alternatives = new HashSet<IMethod>();

        docAPIs.removeAll(removedAPIs);
        for (IMethod m: docAPIs) {
            if (isAlternativeApi(removedApi, m))
                alternatives.add(m);
        }

        // if we have three or more alternatives (e.g. renamed methods with one argument)
        // the suggestions will probably be wrong -> return no alternatives
        if (alternatives.size() > 2)
            return new HashSet<IMethod>();

        return alternatives;
    }



    /**
     * Check for alternative APIs in case an API is no longer available in new library version
     * Tests include
     *   1. whether only the method name was renamed (same descriptor)
     *   2. whether method name/return type are the same but one or more argument types have been generalized
     *      (e.g. ArrayList to List|Collection)
     *   3. Same method one new argument was prepended/appended
     *   4. Same method same arguments, different return type (e.g. String -> String[])
     * @param target
     * @param test
     * @return
     */
    protected static boolean isAlternativeApi(IMethod target, IMethod test) {
        // Test2
        if (isApiCompatible(target, test))
            return true;

        // check whether both APIs reside in the same code Package/Class
        if (! WalaUtils.simpleName(target.getDeclaringClass()).equals(WalaUtils.simpleName(test.getDeclaringClass())))
            return false;

        // check for changes in access specifier
        if (JvmMethodAccessFlags.getMethodAccessCode(target) != JvmMethodAccessFlags.getMethodAccessCode(test)) {
            logger.trace("Access Flags incompatible: old: " + JvmMethodAccessFlags.flags2Str(target) + "   new: " + JvmMethodAccessFlags.flags2Str(test));
            return false;
        }

        // Test1: check whether method was renamed (with same descriptor)
        // Since this is very fuzzy, we further require
        //   - constructors can't be an alternative to non-constructors
        //   - at least one argument  (still fuzzy for methods with one primitive/String arg)
        // TODO:  at least one non-framework arg || at least two prim/framework args
        if (! WalaUtils.getName(target).equals(WalaUtils.getName(test))) {
            int numberOfArgs = target.getNumberOfParameters() - (target.isStatic()? 0 : 1);

            return target.getDescriptor().toString().equals(test.getDescriptor().toString()) &&
                    numberOfArgs > 0 &&
                    (!WalaUtils.getName(target).equals("<init>")) &&
                    (!WalaUtils.getName(test).equals("<init>"));
        }

        // Test3: introduction of new argument at first/last position
        if (WalaUtils.getName(target).equals(WalaUtils.getName(test)) &&   // same method name
            (target.getReturnType().toString().equals(test.getReturnType().toString())) &&   // same return type
            (target.getNumberOfParameters() == test.getNumberOfParameters()-1)) {  // one more arg

            // check if new arg was prepended
            boolean check = true;
            for (int i = (target.isStatic()? 0 : 1); i < target.getNumberOfParameters(); i++) {
                if (!target.getParameterType(i).getName().toString().equals(test.getParameterType(i+1).getName().toString())) {
                    check = false;
                    break;
                }
            }

            if (check) return true;   // prepended

            // check if new arg was appended
            check = true;
            for (int i = (target.isStatic()? 0 : 1); i < target.getNumberOfParameters(); i++) {
                if (!target.getParameterType(i).getName().toString().equals(test.getParameterType(i).getName().toString())) {
                    check = false;
                    break;
                }
            }

            if (check) return true;   // appended
        }

        // Test4: same arg list: different return type
        if (WalaUtils.getName(target).equals(WalaUtils.getName(test)) &&   // same method name
            (!target.getReturnType().toString().equals(test.getReturnType().toString())) &&   // different return type
            (target.getNumberOfParameters() == test.getNumberOfParameters())) {  // same number of args

            // check that all arg types are equal
            boolean equal = true;
            for (int i = (target.isStatic()? 0 : 1); i < target.getNumberOfParameters(); i++) {
                if (!target.getParameterType(i).getName().toString().equals(test.getParameterType(i).getName().toString())) {
                    equal = false;
                    break;
                }
            }

            if (equal) return true;
        }

        return false;
    }


    /**
     * Check whether two API are compatible, i.e. no code changes (calls to APIs) have to be made by app developers
     * This checks whether method name/return type are the same but one or more argument types have been generalized
     * (e.g. ArrayList to List|Collection
     */
    protected static boolean isApiCompatible(IMethod target, IMethod test) {
        // check whether both APIs reside in the same code Package/Class
        if (! WalaUtils.simpleName(target.getDeclaringClass()).equals(WalaUtils.simpleName(test.getDeclaringClass())))
            return false;

        // check for changes in access specifier
        if (JvmMethodAccessFlags.getMethodAccessCode(target) != JvmMethodAccessFlags.getMethodAccessCode(test)) {
            logger.trace("Access Flags incompatible: old: " + JvmMethodAccessFlags.flags2Str(target) + "   new: " + JvmMethodAccessFlags.flags2Str(test));
            return false;
        }

        // check whether method name changed
        if (! WalaUtils.getName(target).equals(WalaUtils.getName(test))) {
            return false;
        }

        // if method name changed, check whether non primitive arguments were generified
        //   - first check wether return types are the same
        if (! target.getReturnType().toString().equals(test.getReturnType().toString()))
            return false;

        //   - check argument types for generalization, i.e. when a ArrayList argument was changed to List
        if (target.getNumberOfParameters() == test.getNumberOfParameters()) {
            for (int i = (target.isStatic()? 0 : 1); i < target.getNumberOfParameters(); i++) {
                if (!target.getParameterType(i).toString().equals(test.getParameterType(i).toString())) {
                    // skip primitive types
                    if (test.getParameterType(i).isPrimitiveType()) return false;

                    // check if test argument type is supertype
                    IClass paramTestClazz = test.getDeclaringClass().getClassHierarchy().lookupClass(test.getParameterType(i));

                    // could be null because it's a type of a different library (sub-dependency) that is not part of the cha
                    if (paramTestClazz == null) {
                        logger.warn("Could not lookup superclazz (maybe sub-dependency):");
                        logger.warn(Utils.INDENT + "target param type: " + target.getParameterType(i).getName().toString());
                        logger.warn(Utils.INDENT + "test param type  : " + test.getParameterType(i).getName().toString());

                        return false;
                    }

                    List<IClass> superClazzes = WalaUtils.getSuperClasses(paramTestClazz);

                    boolean found = false;
                    for (IClass ic: superClazzes) {
                        if (WalaUtils.simpleName(target.getDeclaringClass()).equals(WalaUtils.simpleName(ic))) {
                            found = true;
                            break;
                        }
                    }

                    if (!found)
                        return false;   // incompatible type replacement in test API
                }
            }
            return true;  // all arguments are the same
        }

        return false;

    }


    // IMethod test as IMethod objects stem from different IClassHierarchies
    protected static boolean equals(IMethod m1, IMethod m2) {
        return m1.getSignature().equals(m2.getSignature()) &&
                JvmMethodAccessFlags.getMethodAccessCode(m1) == JvmMethodAccessFlags.getMethodAccessCode(m2);
    }

    protected static VersionWrapper.SEMVER compareApis(Set<IMethod> s0, Set<IMethod> s1) {
        if (s1.containsAll(s0)) {
            if (s0.size() == s1.size())   // exact match
                return VersionWrapper.SEMVER.PATCH;
            else if (s1.size() > s0.size())  // contains complete set of APIs and additions -> backwards-compatible
                return VersionWrapper.SEMVER.MINOR;
        }
        return VersionWrapper.SEMVER.MAJOR;
    }
}
