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

package de.infsec.tpl;

import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import de.infsec.tpl.config.LibScoutConfig;
import de.infsec.tpl.modules.libapi.LibraryApiAnalysis;
import de.infsec.tpl.modules.libmatch.LibraryIdentifier;
import de.infsec.tpl.modules.libprofiler.LibraryProfiler;
import de.infsec.tpl.modules.updatability.LibraryUpdatability;
import de.infsec.tpl.profile.Profile;
import de.infsec.tpl.stats.AppStats;
import org.apache.commons.cli.BasicParser;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.OptionBuilder;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.joran.JoranConfigurator;
import ch.qos.logback.core.joran.spi.JoranException;
import ch.qos.logback.core.util.StatusPrinter;
import de.infsec.tpl.stats.SQLStats;
import de.infsec.tpl.utils.Utils;
import de.infsec.tpl.profile.LibProfile;


public class TplCLI {
	private static final Logger logger = LoggerFactory.getLogger(de.infsec.tpl.TplCLI.class);
	private static Options options;
	
	public static class CliArgs {
		static final String ARG_OPMODE = "o";
		static final String ARGL_OPMODE = "opmode";

		static final String ARG_CONFIG = "c";
		public static final String ARGL_CONFIG = "libscout-conf";

		static final String ARG_ANDROID_LIB = "a";
		static final String ARGL_ANDROID_LIB = "android-sdk";

		static final String ARG_LOG_DIR = "d";
		static final String ARGL_LOG_DIR = "log-dir";

		static final String ARG_STATS_DIR = "s";
		static final String ARGL_STATS_DIR = "stats-dir";

		static final String ARG_JSON_DIR = "j";
		static final String ARGL_JSON_DIR = "json-dir";
		
		static final String ARG_PROFILES_DIR = "p";
		static final String ARGL_PROFILES_DIR = "profiles-dir";
		
		static final String ARG_MUTE = "m";
		static final String ARGL_MUTE = "mute";

		static final String ARG_NO_PARTIAL_MATCHING = "n";
		static final String ARGL_NO_PARTIAL_MATCHING = "no-partial-matching";

		static final String ARG_LIB_USAGE_ANALYSIS = "u";
		static final String ARGL_LIB_USAGE_ANALYSIS = "lib-usage-analysis";

		static final String ARG_LIB_DESCRIPTION = "x";
		static final String ARGL_LIB_DESCRIPTION = "library-description";

		static final String ARG_LIB_VERBOSE_PROFILES = "v";
		static final String ARGL_LIB_VERBOSE_PROFILES = "verbose-profiles";

		static final String ARG_LIB_DEPENDENCY_ANALYSIS = "da";
		static final String ARGL_LIB_DEPENDENCY_ANALYSIS = "lib-dependency-analysis";

		static final String ARG_LIB_API_COMPAT_DIR = "l";
		static final String ARGL_LIB_API_COMPAT_DIR = "lib-api-compat-dir";
	}
	
	private static ArrayList<File> inputFiles;
	private static File libraryDescription = null;

	
	public static void main(String[] args) {
		// parse command line arguments
		parseCL(args);

		List<LibProfile> profiles = null;
		LibraryUpdatability libUp = null;

		try {
			// parse LibScout.toml (args from CLI take precedence)
			LibScoutConfig.loadConfig();

			// sanity check for required options that can be set from both CLI/config file
			checkRequiredOptions();

			// initialize logback
			initLogging();
			LibScoutConfig.whoAmI();

			/*
			 * one time data loading
			 */

			if (LibScoutConfig.opMatch() || LibScoutConfig.opDB() || LibScoutConfig.opUpdatability())
				profiles = Profile.loadLibraryProfiles(LibScoutConfig.profilesDir);

			if (LibScoutConfig.opUpdatability())
				libUp = new LibraryUpdatability(LibScoutConfig.libApiCompatDir);

		} catch (ParseException e) {
			logger.error("Error: " + e.getMessage());
			usage();
		}


		/*
		 * choose mode of operation
		 */

		if (LibScoutConfig.opDB()) {
			// generate SQLite DB from app stats
			SQLStats.stats2DB(profiles);
			System.exit(0);
		}

		// process input files, either library files or apps
		for (File inputFile: inputFiles) {
			try {
				if (LibScoutConfig.opMatch()) {
					LibraryIdentifier.run(inputFile, profiles, LibScoutConfig.runLibUsageAnalysis);

				} else if (LibScoutConfig.opUpdatability()) {
					AppStats stats = LibraryIdentifier.run(inputFile, profiles, true);
					libUp.checkUpdatability(stats);

				} else if (LibScoutConfig.opProfile()) {
					LibraryProfiler.extractFingerPrints(inputFile, libraryDescription);

				} else if (LibScoutConfig.opLibApiAnalysis()) {
					LibraryApiAnalysis.run(inputFile);
				}
			} catch (Throwable t) {
				logger.error("[FATAL " + (t instanceof Exception? "EXCEPTION" : "ERROR") + "] analysis aborted: " + t.getMessage());
				logger.error(Utils.stacktrace2Str(t));
			}
		}
	}


	private static void parseCL(String[] args) {
		try {
			CommandLineParser parser = new BasicParser();
			CommandLine cmd = parser.parse(setupOptions(), args);
		
			// parse mode of operation
			if (cmd.hasOption(CliArgs.ARG_OPMODE)) {
				try {
					LibScoutConfig.opmode = LibScoutConfig.OpMode.valueOf(cmd.getOptionValue(CliArgs.ARG_OPMODE).toUpperCase());
				} catch (IllegalArgumentException e) {
					throw new ParseException(Utils.stacktrace2Str(e));
				}
			} else
				usage();

			/*
			 * Logging options (apply to all modes, default settings: console logging, logdir="./logs")
			 *  -m, disable logging (takes precedence over -d)
			 *  -d [logdir], if provided without argument output is logged to default dir, otherwise to the provided dir
			 */
			if (cmd.hasOption(CliArgs.ARG_MUTE)) {
				LibScoutConfig.logType = LibScoutConfig.LogType.NONE;
			} 
			else if (cmd.hasOption(CliArgs.ARG_LOG_DIR)) {
				LibScoutConfig.logType = LibScoutConfig.LogType.FILE;

				if (cmd.getOptionValue(CliArgs.ARG_LOG_DIR) != null) {   // we have a log dir
					File logDir = new File(cmd.getOptionValue(CliArgs.ARG_LOG_DIR));
					if (logDir.exists() && !logDir.isDirectory())
						throw new ParseException("Log directory " + logDir + " already exists and is not a directory");
					
					LibScoutConfig.logDir = logDir;
				}
			}

			// path to Android SDK jar
			if (checkOptionalUse(cmd, CliArgs.ARG_ANDROID_LIB, LibScoutConfig.OpMode.PROFILE, LibScoutConfig.OpMode.MATCH, LibScoutConfig.OpMode.LIB_API_ANALYSIS, LibScoutConfig.OpMode.UPDATABILITY)) {
				LibScoutConfig.pathToAndroidJar = new File(cmd.getOptionValue(CliArgs.ARG_ANDROID_LIB));
				LibScoutConfig.checkIfValidFile(cmd.getOptionValue(CliArgs.ARG_ANDROID_LIB));
			}

			// path to LibScout.toml
			if (checkOptionalUse(cmd, CliArgs.ARG_CONFIG, LibScoutConfig.OpMode.PROFILE, LibScoutConfig.OpMode.MATCH, LibScoutConfig.OpMode.LIB_API_ANALYSIS, LibScoutConfig.OpMode.DB, LibScoutConfig.OpMode.UPDATABILITY)) {
				LibScoutConfig.libScoutConfigFileName = cmd.getOptionValue(CliArgs.ARG_CONFIG);
				LibScoutConfig.checkIfValidFile(LibScoutConfig.libScoutConfigFileName);
			}

			// profiles dir option, if provided without argument output is written to default dir
			if (checkOptionalUse(cmd, CliArgs.ARG_PROFILES_DIR, LibScoutConfig.OpMode.PROFILE, LibScoutConfig.OpMode.MATCH, LibScoutConfig.OpMode.DB, LibScoutConfig.OpMode.UPDATABILITY)) {
				File profilesDir = new File(cmd.getOptionValue(CliArgs.ARG_PROFILES_DIR));
				if (profilesDir.exists() && !profilesDir.isDirectory())
					throw new ParseException("Profiles directory " + profilesDir + " already exists and is not a directory");
					
				LibScoutConfig.profilesDir = profilesDir;
			}
			
			
			// disable partial matching (full lib matching only)
			if (checkOptionalUse(cmd, CliArgs.ARG_NO_PARTIAL_MATCHING, LibScoutConfig.OpMode.MATCH, LibScoutConfig.OpMode.UPDATABILITY)) {
				LibScoutConfig.noPartialMatching = true;
			}
			
			// run library usage analysis (for full matches only)
			if (checkOptionalUse(cmd, CliArgs.ARG_LIB_USAGE_ANALYSIS, LibScoutConfig.OpMode.MATCH)) {
				LibScoutConfig.runLibUsageAnalysis = true;
			}
			
			// provide library description file
			if (checkRequiredUse(cmd, CliArgs.ARG_LIB_DESCRIPTION, LibScoutConfig.OpMode.PROFILE)) {
				File libraryDescriptionFile = new File(cmd.getOptionValue(CliArgs.ARG_LIB_DESCRIPTION));
				if (libraryDescriptionFile.exists() && libraryDescriptionFile.isDirectory())
					throw new ParseException("Library description (" + libraryDescriptionFile + ") must not be a directory");
					
				libraryDescription = libraryDescriptionFile;
			}

			// generate verbose library profiles?
			if (checkOptionalUse(cmd, CliArgs.ARG_LIB_VERBOSE_PROFILES, LibScoutConfig.OpMode.PROFILE)) {
				LibScoutConfig.genVerboseProfiles = true;
			}

			// enable library dependency analysis
			if (checkOptionalUse(cmd, CliArgs.ARG_LIB_DEPENDENCY_ANALYSIS, LibScoutConfig.OpMode.LIB_API_ANALYSIS)) {
				LibScoutConfig.libDependencyAnalysis = true;
			}

			// enable/disable generation of stats with optional stats directory
			if (checkOptionalUse(cmd, CliArgs.ARG_STATS_DIR, LibScoutConfig.OpMode.MATCH, LibScoutConfig.OpMode.DB)) {
				LibScoutConfig.generateStats = true;

				if (cmd.getOptionValue(CliArgs.ARG_STATS_DIR) != null) {   // stats dir provided?
					File statsDir = new File(cmd.getOptionValue(CliArgs.ARG_STATS_DIR));
					if (statsDir.exists() && !statsDir.isDirectory())
						throw new ParseException("Stats directory " + statsDir + " already exists and is not a directory");
					
					LibScoutConfig.statsDir = statsDir;
				}
			}
			
			// enable/disable generation of json output
			if (checkOptionalUse(cmd, CliArgs.ARG_JSON_DIR, LibScoutConfig.OpMode.MATCH, LibScoutConfig.OpMode.LIB_API_ANALYSIS, LibScoutConfig.OpMode.UPDATABILITY)) {
				LibScoutConfig.generateJSON = true;

				if (cmd.getOptionValue(CliArgs.ARG_JSON_DIR) != null) {   // json dir provided?
					File jsonDir = new File(cmd.getOptionValue(CliArgs.ARG_JSON_DIR));
					if (jsonDir.exists() && !jsonDir.isDirectory())
						throw new ParseException("JSON directory " + jsonDir + " already exists and is not a directory");
					
					LibScoutConfig.jsonDir = jsonDir;
				}
			}

			// provide directory to lib api compat files (generated with api-analysis mode)
			if (checkRequiredUse(cmd, CliArgs.ARG_LIB_API_COMPAT_DIR, LibScoutConfig.OpMode.UPDATABILITY)) {
				File apiCompatDir = new File(cmd.getOptionValue(CliArgs.ARG_LIB_API_COMPAT_DIR));
				if (!apiCompatDir.isDirectory())
					throw new ParseException(apiCompatDir + " is not a directory");

				LibScoutConfig.libApiCompatDir = apiCompatDir;
			}


			/*
			 * process lib|app arguments
			 *  - in profile mode pass *one* library (since it is linked to lib description file)
			 *  - in match mode pass one application file or one directory (including apks)
			 */
			if (!(LibScoutConfig.opDB())) {
				inputFiles = new ArrayList<File>();

				if (LibScoutConfig.opLibApiAnalysis()) {
					// we require a directory including library packages/descriptions
					for (String path: cmd.getArgs()) {
						File dir = new File(path);

						if (dir.isDirectory())
							inputFiles.add(dir);
					}

					if (inputFiles.isEmpty()) {
						throw new ParseException("You have to provide at least one directory that includes a library package and description");
					}
				} else {
					String[] fileExts = LibScoutConfig.opMatch() || LibScoutConfig.opUpdatability() ? new String[]{"apk"} : new String[]{"jar", "aar"};

					for (String inputFile : cmd.getArgs()) {
						File arg = new File(inputFile);

						if (arg.isDirectory()) {
							inputFiles.addAll(Utils.collectFiles(arg, fileExts));
						} else if (arg.isFile()) {
							if (arg.getName().endsWith("." + fileExts[0]))
								inputFiles.add(arg);
							else if (fileExts.length > 1 && arg.getName().endsWith("." + fileExts[1]))
								inputFiles.add(arg);
							else
								throw new ParseException("File " + arg.getName() + " is no valid ." + Utils.join(Arrays.asList(fileExts), "/") + " file");
						} else {
							throw new ParseException("Argument " + inputFile + " is no valid file or directory!");
						}
					}

					if (inputFiles.isEmpty()) {
						if (LibScoutConfig.opProfile())
							throw new ParseException("No libraries (jar|aar files) found to profile in "  + cmd.getArgList());
						else
							throw new ParseException("No apk files found in " + cmd.getArgList());
					} else if (inputFiles.size() > 1 && LibScoutConfig.opProfile())
						throw new ParseException("You have to provide a path to a single library file or a directory incl. a single lib file");
				}
			}
			
		} catch (ParseException e) {
			System.err.println("Command line parsing failed:\n  " + e.getMessage() + "\n");
			usage();
		} catch (Exception e) {
			System.err.println("Error occurred during argument processing:\n" + e.getMessage());
		}
	}
	
	

	private static boolean checkRequiredUse(CommandLine cmd, String option, LibScoutConfig.OpMode... modes) throws ParseException {
		if (!Arrays.asList(modes).contains(LibScoutConfig.opmode))
			return false;
		
		if (!cmd.hasOption(option))
			throw new ParseException("Required CLI Option " + option + " is missing in mode " + LibScoutConfig.opmode);
		
		return true;
	}
	
	
	private static boolean checkOptionalUse(CommandLine cmd, String option, LibScoutConfig.OpMode... modes) {
		if (!Arrays.asList(modes).contains(LibScoutConfig.opmode))
			return false;

		return cmd.hasOption(option);
	}

	/**
	  * Checks whether required option (for current mode) is either provided via CLI or config file
	  */
	private static void checkRequiredOptions() throws ParseException {
		try {
			LibScoutConfig.checkIfValidFile(LibScoutConfig.log4jConfigFileName);
		} catch (ParseException e) {
			throw new ParseException("Could not find the log4j config file logback.xml . Please add the path in the LibScout.toml config");
		}

		// android-sdk.jar
		if (Arrays.asList(LibScoutConfig.OpMode.PROFILE, LibScoutConfig.OpMode.MATCH, LibScoutConfig.OpMode.LIB_API_ANALYSIS).contains(LibScoutConfig.opmode) &&
			LibScoutConfig.pathToAndroidJar == null) {
			throw new ParseException("Required option " + CliArgs.ARGL_ANDROID_LIB + " is neither provided via command line nor config file");
		}
	}

	
	@SuppressWarnings("static-access")
	private static Options setupOptions() {
		options = new Options();

		options.addOption(OptionBuilder.withArgName("value")
			.hasArgs(1)
            .isRequired(true)
            .withLongOpt(CliArgs.ARGL_OPMODE)
            .withDescription("mode of operation, one of [" + LibScoutConfig.OpMode.getOpModeString() + "]")
            .create(CliArgs.ARG_OPMODE));

		options.addOption(OptionBuilder.withArgName("file")
			.hasArgs(1)
			.isRequired(false)
			.withLongOpt(CliArgs.ARGL_CONFIG)
			.withDescription("path to LibScout's config file, defaults to \"" + LibScoutConfig.libScoutConfigFileName + "\"")
			.create(CliArgs.ARG_CONFIG));

		options.addOption(OptionBuilder.withArgName("file")
			.hasArgs(1)
            .isRequired(false)
            .withLongOpt(CliArgs.ARGL_ANDROID_LIB)
            .withDescription("path to SDK android.jar")
            .create(CliArgs.ARG_ANDROID_LIB));

		options.addOption(OptionBuilder.withArgName("directory")
			.hasOptionalArgs(1)
	        .isRequired(false)
	        .withLongOpt(CliArgs.ARGL_LOG_DIR)
	        .withDescription("path to store the logfile(s), defaults to \"" + LibScoutConfig.logDir + "\"")
	        .create(CliArgs.ARG_LOG_DIR));

		options.addOption(OptionBuilder.withArgName("directory")
			.hasOptionalArgs(1)
	        .isRequired(false)
	        .withLongOpt(CliArgs.ARGL_STATS_DIR)
	        .withDescription("path to app stat(s), defaults to \"" + LibScoutConfig.statsDir + "\"")
	        .create(CliArgs.ARG_STATS_DIR));

		options.addOption(OptionBuilder.withArgName("directory")
			.hasOptionalArgs(1)
	        .isRequired(false)
	        .withLongOpt(CliArgs.ARGL_JSON_DIR)
	        .withDescription("path to json output directory, defaults to \"" + LibScoutConfig.jsonDir + "\"")
	        .create(CliArgs.ARG_JSON_DIR));
		
		options.addOption(OptionBuilder.withArgName("value")
	        .isRequired(false)
	        .withLongOpt(CliArgs.ARGL_MUTE)
	        .withDescription("disable file and console logging, takes precedence over -d")
	        .create(CliArgs.ARG_MUTE));
		
		options.addOption(OptionBuilder.withArgName("directory")
			.hasArgs(1)
	        .isRequired(false)
	        .withLongOpt(CliArgs.ARGL_PROFILES_DIR)
	        .withDescription("path to library profiles, defaults to \"" + LibScoutConfig.profilesDir + "\"")
	        .create(CliArgs.ARG_PROFILES_DIR));

		options.addOption(OptionBuilder.withArgName("value")
			.isRequired(false)
			.withLongOpt(CliArgs.ARGL_LIB_VERBOSE_PROFILES)
			.withDescription("enable verbose profiling (trace + pubonly)")
			.create(CliArgs.ARG_LIB_VERBOSE_PROFILES));

		options.addOption(OptionBuilder.withArgName("value")
	        .isRequired(false)
	        .withLongOpt(CliArgs.ARGL_NO_PARTIAL_MATCHING)
	        .withDescription("disables partial matching (full matching only)")
	        .create(CliArgs.ARG_NO_PARTIAL_MATCHING));

		options.addOption(OptionBuilder.withArgName("value")
	        .isRequired(false)
	        .withLongOpt(CliArgs.ARGL_LIB_USAGE_ANALYSIS)
	        .withDescription("Enables library usage analysis (for full matches only)")
	        .create(CliArgs.ARG_LIB_USAGE_ANALYSIS));
		
		options.addOption(OptionBuilder.withArgName("file")
			.hasArgs(1)
	        .isRequired(false)
	        .withLongOpt(CliArgs.ARGL_LIB_DESCRIPTION)
	        .withDescription("xml file to describe the library")
	        .create(CliArgs.ARG_LIB_DESCRIPTION));

		options.addOption(OptionBuilder.withArgName("value")
			.isRequired(false)
			.withLongOpt(CliArgs.ARGL_LIB_DEPENDENCY_ANALYSIS)
			.withDescription("enable analysis of secondary library dependencies")
			.create(CliArgs.ARG_LIB_DEPENDENCY_ANALYSIS));

		options.addOption(OptionBuilder.withArgName("directory")
			.hasArgs(1)
			.isRequired(false)
			.withLongOpt(CliArgs.ARGL_LIB_API_COMPAT_DIR)
			.withDescription("path to library api compatibility data files")
			.create(CliArgs.ARG_LIB_API_COMPAT_DIR));

		return options;
	}

	
	private static void usage() {
		// automatically generate the help statement
		HelpFormatter formatter = new HelpFormatter();
		String helpMsg = LibScoutConfig.OpMode.getUsageMessage(LibScoutConfig.opmode);
		formatter.printHelp(helpMsg, options);
		System.exit(1);
	}

	private static void initLogging() {
		LoggerContext context = (LoggerContext) org.slf4j.LoggerFactory.getILoggerFactory();
		    
		try {
			JoranConfigurator configurator = new JoranConfigurator();
		    configurator.setContext(context);
		    context.reset();  // clear any previous configuration 
		    configurator.doConfigure(LibScoutConfig.log4jConfigFileName);
		    
	    	ch.qos.logback.classic.Logger rootLogger = (ch.qos.logback.classic.Logger) LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);
	    	switch (LibScoutConfig.logType) {
				case CONSOLE:
					rootLogger.detachAppender("FILE");
					break;
				case FILE:
					rootLogger.detachAppender("CONSOLE");
					break;
				case NONE:
					rootLogger.detachAndStopAllAppenders();
					break;
	    	}
		} catch (JoranException je) {
			// StatusPrinter will handle this
		}
		
		StatusPrinter.printInCaseOfErrorsOrWarnings(context);
	}

}
