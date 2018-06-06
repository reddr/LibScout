package de.infsec.tpl.modules.libapi;

import com.ibm.wala.classLoader.IMethod;
import de.infsec.tpl.utils.Utils;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

/**
 * Spec taken from https://docs.oracle.com/javase/specs/jvms/se7/html/jvms-4.html
 */
public enum JvmMethodAccessFlags {

    NO_FLAG   (0x0000, "no-flag"),
    PUBLIC    (0x0001, "public"),
    PRIVATE   (0x0002, "private"),
    PROTECTED (0x0004, "protected"),
    STATIC    (0x0008, "static"),
    FINAL     (0x0010, "final"),
    ABSTRACT  (0x0400, "abstract"),
    PACKAGE_PROTECTED (0x2000, "package-proteced");

    private int value;
    private String accessFlagName;

    //cache the array of all AccessFlags, because .values() allocates a new array for every call
    private final static JvmMethodAccessFlags[] allFlags;

    private final static List<Integer> validFlagValues;

    private static HashMap<String, JvmMethodAccessFlags> accessFlagsByName;

    static {
        allFlags = JvmMethodAccessFlags.values();

        validFlagValues = new ArrayList<Integer>();
        for (JvmMethodAccessFlags flag: allFlags)
            validFlagValues.add(flag.getValue());

        accessFlagsByName = new HashMap<String, JvmMethodAccessFlags>();
        for (JvmMethodAccessFlags accessFlag: allFlags) {
            accessFlagsByName.put(accessFlag.accessFlagName, accessFlag);
        }
    }

    private JvmMethodAccessFlags(int value, String accessFlagName) {
        this.value = value;
        this.accessFlagName = accessFlagName;
    }


    private static String flags2Str(JvmMethodAccessFlags[] accessFlags) {
        int size = 0;
        for (JvmMethodAccessFlags accessFlag: accessFlags) {
            size += accessFlag.toString().length() + 1;
        }

        StringBuilder sb = new StringBuilder(size);
        for (JvmMethodAccessFlags accessFlag: accessFlags) {
            sb.append(accessFlag.toString());
            sb.append(" ");
        }
        if (accessFlags.length > 0) {
            sb.delete(sb.length() - 1, sb.length());
        }
        return sb.toString();
    }

    public static boolean isValidFlag(int code) {
        return validFlagValues.contains(code);
    }


    public static String flags2Str(int code) {
        List<String> matchedFlags = new ArrayList<String>();

        for (JvmMethodAccessFlags flag: allFlags) {
            if ((code & flag.value) != 0x0) {
                matchedFlags.add(flag.accessFlagName + "(" + flag.value + ")");
            }
        }

        return Utils.join(matchedFlags, ",");
    }

    public static String flags2Str(IMethod m) {
        return flags2Str(getMethodAccessCode(m));
    }

    public static JvmMethodAccessFlags getAccessFlag(String accessFlag) {
        return accessFlagsByName.get(accessFlag);
    }

    public int getValue() {
        return value;
    }

    public String toString() {
        return accessFlagName;
    }


    public static int getAccessFlagFilter(JvmMethodAccessFlags... flags) {
        int filter = NO_FLAG.getValue();

        if (flags != null) {
            for (JvmMethodAccessFlags flag: flags) {
                if (!JvmMethodAccessFlags.isValidFlag(flag.getValue())) continue;

                filter |= flag.getValue();
            }
        }

        return filter;
    }

    public static int getPublicOnlyFilter() {
        return getAccessFlagFilter(JvmMethodAccessFlags.PRIVATE, JvmMethodAccessFlags.PROTECTED, JvmMethodAccessFlags.STATIC,
                JvmMethodAccessFlags.FINAL, JvmMethodAccessFlags.ABSTRACT, JvmMethodAccessFlags.PACKAGE_PROTECTED);
    }


    public static int getMethodAccessCode(IMethod m) {
        int res = 0x0;

        if (m == null)
            return res;

        if (m.isPublic()) {
            res |= JvmMethodAccessFlags.PUBLIC.getValue();
        } else if (m.isProtected()) {
            res |= JvmMethodAccessFlags.PROTECTED.getValue();
        } else if (m.isPrivate()) {
            res |= JvmMethodAccessFlags.PRIVATE.getValue();
        } else {
            res |= JvmMethodAccessFlags.PACKAGE_PROTECTED.getValue();
        }

        if (m.isStatic())
            res |= JvmMethodAccessFlags.STATIC.getValue();
        if (m.isFinal())
            res |= JvmMethodAccessFlags.FINAL.getValue();
        if (m.isAbstract())
            res |= JvmMethodAccessFlags.ABSTRACT.getValue();

        return res;
    }

}
