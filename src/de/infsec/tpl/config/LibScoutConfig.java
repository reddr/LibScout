package de.infsec.tpl.config;

import de.infsec.tpl.TplCLI;
import de.infsec.tpl.utils.Utils;
import net.consensys.cava.toml.Toml;
import net.consensys.cava.toml.TomlParseResult;
import org.apache.commons.cli.ParseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.stream.Collectors;


public class LibScoutConfig {
    private static final Logger logger = LoggerFactory.getLogger(de.infsec.tpl.config.LibScoutConfig.class);

    public static final String TOOLNAME = "LibScout";
    public static final String TOOLVERSION = "2.1.0";

    // modes of operations
    public enum OpMode {
        // generate library profiles from original lib SDKs and descriptions
        PROFILE("profile", "-x path_to_lib_desc [options] path_to_lib(jar|aar)"),

        // match lib profiles in provided apps
        MATCH("match", "[options] path_to_app(dir)"),

        // build sqlite database from app stat files
        DB("db", "-p path_to_profiles -s path_to_stats"),

        // analyzes library api stability (api additions, removals, changes)
        LIB_API_ANALYSIS("lib_api_analysis", "path_to_lib_sdks");

        // infer library usage in apps and check to which extent detected libs can be updated
      //  UPDATABILITY( "updatability",  "[options] -l path_to_lib_api_compat path_to_app(dir)");

        public String name;
        public String usageMsg;

        OpMode(String name, String usageMsg) {
            this.name = name;
            this.usageMsg = usageMsg;
        }

        public static String getUsageMessage(OpMode op) {
            return op == null? getToolUsageMsg() : TOOLNAME + " --opmode " + op.name + " " + op.usageMsg;
        }

        public static String getToolUsageMsg() {
            return TOOLNAME + " --opmode <" + getOpModeString() + "> [options]";
        }

        public static String getOpModeString() {
            return Utils.join(Arrays.stream(OpMode.values()).map(op -> op.name.toLowerCase()).collect(Collectors.toList()), "|");
        }
    }

    public static OpMode opmode = null;
    public static boolean opMatch() { return OpMode.MATCH.equals(opmode); }
    public static boolean opProfile() { return OpMode.PROFILE.equals(opmode); }
    public static boolean opDB() { return OpMode.DB.equals(opmode); }
    public static boolean opLibApiAnalysis() { return OpMode.LIB_API_ANALYSIS.equals(opmode); }


    // config files
    public static String libScoutConfigFileName = "./config/LibScout.toml";
    public static String log4jConfigFileName = "./config/logback.xml";

    public static File pathToAndroidJar;

    public static boolean noPartialMatching = false;
    public static boolean runLibUsageAnalysis = false;
    public static boolean genVerboseProfiles = false;   // generate lib profiles with TRACE + PubOnly

    public static boolean libDependencyAnalysis = false;


    public enum LogType { NONE, CONSOLE, FILE }
    public static LogType logType = LogType.CONSOLE;
    public static File logDir = new File("./logs");

    public static boolean generateStats = false;
    public static File statsDir = new File("./stats");

    public static boolean generateJSON = false;
    public static File jsonDir = new File("./json");

    public static File profilesDir = new File("./profiles");

    // package tree
    public static class PckgTree {
        public static boolean useAsciiRendering = false;
    }


    public static void whoAmI() {
        logger.info("This is " + TOOLNAME + " " + TOOLVERSION);
    }

    public static boolean loadConfig() throws ParseException {
        File libScoutConfigFile;
        try {
            libScoutConfigFile = checkIfValidFile(libScoutConfigFileName);
        } catch (ParseException e) {
            throw new ParseException("Could not find the config file LibScout.toml . Please provide it via the --" + TplCLI.CliArgs.ARGL_CONFIG + " switch");
        }

        try {
            Path confPath = Paths.get(libScoutConfigFile.toURI());
            TomlParseResult conf = Toml.parse(confPath);

            if (conf.hasErrors()) {
                logger.warn("Error while parsing config file:");
                conf.errors().forEach(e -> logger.info(Utils.indent() + "line: " + e.position().line() + ": " + e.toString()));
                return false;
            } else {
                for (String k: conf.dottedKeySet()) {
                    parseConfig(k, conf.get(k));
                }
            }

        } catch (IOException e) {
            logger.warn("Error while parsing config file: " + Utils.stacktrace2Str(e));
            return false;
        }

        return true;
    }

    private static void parseConfig(String key, Object value) throws ParseException {
        try {
            //logger.debug("Parse config key : " + key + "   value: " + value);

            if ("logging.log4j_config_file".equals(key)) {
                File f = checkIfValidFile((String) value);
                log4jConfigFileName = f.getAbsolutePath();

            } else if ("sdk.android_sdk_jar".equals(key)) {
                if (pathToAndroidJar == null)  // CLI takes precedence
                    pathToAndroidJar = checkIfValidFile((String) value);

            } else if ("packageTree.ascii_rendering".equals(key)) {
                PckgTree.useAsciiRendering = (Boolean) value;

            } else
                logger.warn("Found unknown config key: " + key);

        } catch (ParseException e) {
           throw new ParseException("Could not parse config option " + key + " : " + e.getMessage());
        }
    }

    public static File checkIfValidFile(String fileName) throws ParseException {
        File f = new File(fileName);
        if (f.exists() && f.isFile())
            return f;
        else
            throw new ParseException("No valid file: " + fileName);
    }
}
