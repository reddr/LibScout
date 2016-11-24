/*
 * Copyright (c) 2015-2016  Erik Derr [derr@cs.uni-saarland.de]
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
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

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
	
    /*
     *  mode of operation
     *    - PROFILE:  generate library profiles from original lib SDKs and descriptions
     *    -   MATCH:  match lib profiles in provided apps
     *    -      DB:  build sqlite database from app stat files 
     */
	public static  enum OpMode {PROFILE, MATCH, DB};
	
	public static class CliOptions {
		public static File pathToAndroidJar;		
		public static Utils.LOGTYPE logType = Utils.LOGTYPE.CONSOLE;
		public static File logDir = new File("./logs");
		public static File statsDir = new File("./stats");
		public static File profilesDir = new File("./profiles");
		public static OpMode opmode = null;
		
		public static boolean noPartialMatching = false;
		public static boolean generateStats = false;
	}
	
	public static class LibProfiles {
		public static List<LibProfile> profiles;
	}
	
	private static final String TOOLNAME = "LibScout";
	private static final String USAGE = TOOLNAME + " --opmode [profile|match|db] <options>";
	private static final String USAGE_PROFILE = TOOLNAME + " --opmode profile -a <path-to-android.jar> -x <path-to-lib-desc> <options> $lib.jar";
	private static final String USAGE_MATCH = TOOLNAME + " --opmode match -a <path-to-android.jar> <options> $path-to-app(-dir)";
	private static final String USAGE_DB = TOOLNAME + " --opmode db -p <path-to-profiles> -s <path-to-stats>";
	private static ArrayList<File> targetFiles;
	private static File libraryDescription = null;
	protected static long libProfileLoadingTime = 0l;

	
	public static void main(String[] args) {
		// parse command line arguments
		parseCL(args);

		// initialize logback
		initLogging();

		List<LibProfile> profiles = null;
		if (!CliOptions.opmode.equals(OpMode.PROFILE)) {
			try {
				profiles = loadLibraryProfiles();
			} catch (Exception e) {}
			
			if (profiles == null || profiles.isEmpty()) {
				System.err.println("No profiles found in " + CliOptions.profilesDir + ". Check your settings!");
				System.exit(1);
			}
		}

		// generate SQLite DB from app stats only
		if (CliOptions.opmode.equals(OpMode.DB)) {
			SQLStats.stats2DB(profiles);
			System.exit(0);
		} 
				
		for (File targetFile: targetFiles) {
			LibraryHandler handler = new LibraryHandler(targetFile, libraryDescription, profiles);
			handler.run();
		}
	}

	
	public static List<LibProfile> loadLibraryProfiles() throws ClassNotFoundException, IOException {
		// de-serialize library profiles
		long s = System.currentTimeMillis();
		List<LibProfile> profiles = new ArrayList<LibProfile>();
		for (File f: Utils.collectFiles(CliOptions.profilesDir, new String[]{"lib"})) {
			LibProfile fp = (LibProfile) Utils.disk2Object(f);
			profiles.add(fp);
		}
		
		Collections.sort(profiles, LibProfile.comp);
		libProfileLoadingTime = System.currentTimeMillis() - s;
		
		return profiles;
	}

	
	
	private static void parseCL(String[] args) {
		try {
			CommandLineParser parser = new BasicParser();
			CommandLine cmd = parser.parse(setupOptions(), args);
		
			// parse mode of operation
			if (cmd.hasOption("o")) {
				try {
					CliOptions.opmode = OpMode.valueOf(cmd.getOptionValue("o").toUpperCase());
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
			if (cmd.hasOption("m")) {
				CliOptions.logType = Utils.LOGTYPE.NONE;
			} 
			else if (cmd.hasOption("d")) {
				CliOptions.logType = Utils.LOGTYPE.FILE;

				if (cmd.getOptionValue("d") != null) {   // we have a log dir
					File logDir = new File(cmd.getOptionValue("d"));
					if (logDir.exists() && !logDir.isDirectory())
						throw new ParseException("Log directory " + logDir + " already exists and is not a directory");
					
					CliOptions.logDir = logDir;
				}
			}

			// path to Android SDK jar
			if (checkRequiredUse(cmd, "a", OpMode.PROFILE, OpMode.MATCH)) {
				CliOptions.pathToAndroidJar = new File(cmd.getOptionValue("a"));
			}
			
			
			// profiles dir option, if provided without argument output is written to default dir
			if (checkOptionalUse(cmd, "p", OpMode.PROFILE, OpMode.MATCH, OpMode.DB)) {
				File profilesDir = new File(cmd.getOptionValue("p"));
				if (profilesDir.exists() && !profilesDir.isDirectory())
					throw new ParseException("Profiles directory " + profilesDir + " already exists and is not a directory");
					
				CliOptions.profilesDir = profilesDir;
			}
			
			
			// disable partial matching (full lib matching only)
			if (checkOptionalUse(cmd, "n", OpMode.MATCH)) {
				CliOptions.noPartialMatching = true;
			}
			
			
			// provide library description file
			if (checkRequiredUse(cmd, "x", OpMode.PROFILE)) {
				File libraryDescriptionFile = new File(cmd.getOptionValue("x"));
				if (libraryDescriptionFile.exists() && libraryDescriptionFile.isDirectory())
					throw new ParseException("Library description (" + libraryDescriptionFile + ") must not be a directory");
					
				libraryDescription = libraryDescriptionFile;
			}

			
			// enable/disable generation of stats with optional stats directory
			if (checkOptionalUse(cmd, "s", OpMode.MATCH, OpMode.DB)) {
				CliOptions.generateStats = true;

				if (cmd.getOptionValue("s") != null) {   // stats dir provided?
					File statsDir = new File(cmd.getOptionValue("s"));
					if (statsDir.exists() && !statsDir.isDirectory())
						throw new ParseException("Stats directory " + statsDir + " already exists and is not a directory");
					
					CliOptions.statsDir = statsDir;
				}
			}
			
			
			/*
			 * process lib|app arguments
			 *  - in profile mode pass *one* library (since it is linked to lib description file)
			 *  - in match mode pass one application file or one directory file (including apks)
			 */
			if (!CliOptions.opmode.equals(OpMode.DB)) {
				targetFiles = new ArrayList<File>();
				String fileExt = CliOptions.opmode.equals(OpMode.MATCH)? "apk" : "jar"; 

				for (String apkFileName: cmd.getArgs()) {
					File arg = new File(apkFileName);
					if (arg.isDirectory()) {
						targetFiles.addAll(Utils.collectFiles(arg, new String[]{fileExt}));
					} else if (arg.isFile()) {
						if (arg.getName().endsWith("." + fileExt))
							targetFiles.add(arg);
						else
							throw new ParseException("File " + arg.getName() + " is no valid ." + fileExt + " file");
					} else {
						throw new ParseException("Argument is no valid file or directory!");
					}
				}
				
				if (targetFiles.isEmpty()) {
					if (CliOptions.opmode.equals(OpMode.PROFILE))
						throw new ParseException("You have to provide one library.jar to be processed");
					else
						throw new ParseException("You have to provide a path to a single application file or a directory");
				} else if (targetFiles.size() > 1 && CliOptions.opmode.equals(OpMode.PROFILE))
					throw new ParseException("You have to provide a path to a single library file or a directory incl. a single lib file");
			}
			
		} catch (ParseException e) {
			System.err.println("Command line parsing failed:\n" + e.getMessage());
			usage();
		} catch (Exception e) {
			System.err.println("Error occured during argument processing:\n" + e.getMessage());
		}
	}
	
	

	private static boolean checkRequiredUse(CommandLine cmd, String option, OpMode... modes) throws ParseException {
		if (!Arrays.asList(modes).contains(CliOptions.opmode))
			return false;
		
		if (!cmd.hasOption(option))
			throw new ParseException("Required CLI Option " + option + " is missing in mode " + CliOptions.opmode);
		
		return true;
	}
	
	
	private static boolean checkOptionalUse(CommandLine cmd, String option, OpMode... modes) throws ParseException {
		if (!Arrays.asList(modes).contains(CliOptions.opmode))
			return false;
		
		if (!cmd.hasOption(option))
			return false;
		
		return true;
	}

	
	
	@SuppressWarnings("static-access")
	private static Options setupOptions() {
		options = new Options();

		options.addOption(OptionBuilder.withArgName("value")
			.hasArgs(1)
            .isRequired(true)
            .withLongOpt("opmode")
            .withDescription("mode of operation, one of [profile|match|db]")
            .create("o"));
		
		options.addOption(OptionBuilder.withArgName("file")
			.hasArgs(1)
            .isRequired(false)
            .withLongOpt("android-library")
            .withDescription("path to SDK android.jar")
            .create("a"));

		options.addOption(OptionBuilder.withArgName("directory")
			.hasOptionalArgs(1)
	        .isRequired(false)
	        .withLongOpt("log-dir")
	        .withDescription("path to store the logfile(s), defaults to \"./logs\"")
	        .create("d"));

		options.addOption(OptionBuilder.withArgName("directory")
			.hasOptionalArgs(1)
	        .isRequired(false)
	        .withLongOpt("stats-dir")
	        .withDescription("path to app stat(s), defaults to \"./stats\"")
	        .create("s"));
		
		options.addOption(OptionBuilder.withArgName("value")
	        .isRequired(false)
	        .withLongOpt("mute")
	        .withDescription("disable file and console logging, takes precedence over -d")
	        .create("m"));
		
		options.addOption(OptionBuilder.withArgName("directory")
			.hasArgs(1)
	        .isRequired(false)
	        .withLongOpt("profiles-dir")
	        .withDescription("path to library profiles, defaults to \"./profiles\"")
	        .create("p"));

		options.addOption(OptionBuilder.withArgName("value")
	        .isRequired(false)
	        .withLongOpt("no-partial-matching")
	        .withDescription("disables partial matching (full matching only)")
	        .create("n"));
		
		options.addOption(OptionBuilder.withArgName("file")
			.hasArgs(1)
	        .isRequired(false)
	        .withLongOpt("library-description")
	        .withDescription("xml file to describe the library")
	        .create("x"));
		
		return options;
	}

	
	private static void usage() {
		// automatically generate the help statement
		HelpFormatter formatter = new HelpFormatter();
		String helpMsg = USAGE;
		if (OpMode.PROFILE.equals(CliOptions.opmode))
			helpMsg = USAGE_PROFILE;
		else if (OpMode.MATCH.equals(CliOptions.opmode))
			helpMsg = USAGE_MATCH;
		else if (OpMode.DB.equals(CliOptions.opmode))
			helpMsg = USAGE_DB;

		formatter.printHelp(helpMsg, options);
		System.exit(1);
	}
	
	
	private static void initLogging() {
		LoggerContext context = (LoggerContext) org.slf4j.LoggerFactory.getILoggerFactory();
		    
		try {
			JoranConfigurator configurator = new JoranConfigurator();
		    configurator.setContext(context);
		    context.reset();  // clear any previous configuration 
		    configurator.doConfigure("./logging/logback.xml");   
		    
	    	ch.qos.logback.classic.Logger rootLogger = (ch.qos.logback.classic.Logger) LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);
	    	switch (CliOptions.logType) {
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
