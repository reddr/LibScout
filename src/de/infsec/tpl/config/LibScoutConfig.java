package de.infsec.tpl.config;

import java.io.File;


public class LibScoutConfig {
    public enum LogType { NONE, CONSOLE, FILE };

    /*
     *  mode of operations
     *    -          PROFILE:  generate library profiles from original lib SDKs and descriptions
     *    -            MATCH:  match lib profiles in provided apps
     *    -               DB:  build sqlite database from app stat files
     *    - LIB_API_ANALYSIS:  analyzes library api stability (api additions, removals, changes)
     */
    public enum OpMode {PROFILE, MATCH, DB, LIB_API_ANALYSIS};


    public static File pathToAndroidJar;

    public static LogType logType = LogType.CONSOLE;
    public static File logDir = new File("./logs");

    public static boolean generateStats = false;
    public static File statsDir = new File("./stats");

    public static boolean generateJSON = false;
    public static File jsonDir = new File("./json");


    public static File profilesDir = new File("./profiles");


    public static OpMode opmode = null;

    public static boolean noPartialMatching = false;
    public static boolean runLibUsageAnalysis = false;
    public static boolean genVerboseProfiles = false;   // generate lib profiles with TRACE + PubOnly

    public static boolean libDependencyAnalysis = false;




    public static boolean opMatch() { return OpMode.MATCH.equals(opmode); }
    public static boolean opProfile() { return OpMode.PROFILE.equals(opmode); }
    public static boolean opDB() { return OpMode.DB.equals(opmode); }
    public static boolean opLibApiAnalysis() { return OpMode.LIB_API_ANALYSIS.equals(opmode); }
}
