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
	
	public static class CliOptions {
		public static File pathToAndroidJar;		
		public static Utils.LOGTYPE logType = Utils.LOGTYPE.CONSOLE;
		public static File logDir = new File("./logs");
		public static File statsDir = new File("./stats");
		public static File profilesDir = new File("./profiles");
		public static boolean createDB = false;
		public static boolean isMatchingMode = true;
		public static boolean noPartialMatching = false;
	}
	
	public static class LibProfiles {
		public static List<LibProfile> profiles;
	}
	
	private static final String TOOLNAME = "LibScout";
	private static final String USAGE = TOOLNAME + " <options> <path to lib.jar>";
	private static ArrayList<File> targetFiles;
	private static File libraryDescription = null;
	protected static long libProfileLoadingTime = 0l;

	
	public static void main(String[] args) {
		// parse command line arguments
		parseCL(args);

		// initialize logback
		initLogging();

		// generate SQLite DB from app stats only
		if (CliOptions.createDB) {
			SQLStats.stats2DB();
			System.exit(0);
		} 
		
		List<LibProfile> profiles = null;
		if (CliOptions.isMatchingMode) {
			try {
				profiles = loadLibraryProfiles();
				//SQLStats.updateLibProfiles(profiles);  // write LibProfiles to DB once
			} catch (Exception e) {
				logger.error(Utils.stacktrace2Str(e));
				System.exit(1);
			}
		}
		
		for (File targetFile: targetFiles) {
			LibraryHandler handler = new LibraryHandler(targetFile, libraryDescription, profiles);
			handler.run();
		}
	}

	
	public static List<LibProfile> loadLibraryProfiles() throws ClassNotFoundException, IOException {
		// de-serialize library profiles
//		logger.info("= Load library profiles =");
		long s = System.currentTimeMillis();
		List<LibProfile> profiles = new ArrayList<LibProfile>();
		for (File f: Utils.collectFiles(CliOptions.profilesDir, new String[]{"data"})) {
			LibProfile fp = (LibProfile) Utils.deSerializeObjectFromDisk(f);
			profiles.add(fp);
		}
		
		Collections.sort(profiles, LibProfile.comp);
//		Set<String> uniqueLibraries = LibProfile.getUniqueLibraries(profiles);
//		logger.info(LogConfig.INDENT + "Loaded " + uniqueLibraries.size() + " unique libraries with "+ profiles.size() + " library profiles (in " + Utils.millisecondsToFormattedTime(System.currentTimeMillis() - s) + ")");
//		logger.info("");
		libProfileLoadingTime = System.currentTimeMillis() - s;
		
		return profiles;
	}

	
	
	private static void parseCL(String[] args) {
		try {
			CommandLineParser parser = new BasicParser();
			CommandLine cmd = parser.parse(setupOptions(), args);
			
			// process options
			if (cmd.hasOption("a"))
                CliOptions.pathToAndroidJar = new File(cmd.getOptionValue("a"));
			
			// Logdir option, if provided without argument output is logged to default dir, otherwise to the provided dir
			if (cmd.hasOption("d")) {
				CliOptions.logType = Utils.LOGTYPE.FILE;

				if (cmd.getOptionValue("d") != null) {   // we have a log dir
					File logDir = new File(cmd.getOptionValue("d"));
					if (logDir.exists() && !logDir.isDirectory())
						throw new ParseException("Log directory " + logDir + " already exists and is not a directory");
					
					CliOptions.logDir = logDir;
				}
			}
			
			// profiles dir option, if provided without argument output is written to default dir
			if (cmd.hasOption("p")) {
				File profilesDir = new File(cmd.getOptionValue("p"));
				if (profilesDir.exists() && !profilesDir.isDirectory())
					throw new ParseException("Profiles directory " + profilesDir + " already exists and is not a directory");
					
				CliOptions.profilesDir = profilesDir;
			}
			
			
			// disable partial matching (full lib matching only)
			if (cmd.hasOption("n")) {
				CliOptions.noPartialMatching = true;
			}
			
			// if a library description is provided we are in extraction mode
			if (cmd.hasOption("x")) {
				File libraryDescriptionFile = new File(cmd.getOptionValue("x"));
				if (libraryDescriptionFile.exists() && libraryDescriptionFile.isDirectory())
					throw new ParseException("Library description (" + libraryDescriptionFile + ") must not be a directory");
					
				libraryDescription = libraryDescriptionFile;
				CliOptions.isMatchingMode = false;
			}

			
			if (cmd.hasOption("db")) {
				CliOptions.createDB = true;

				if (cmd.getOptionValue("db") != null) {   // we have a stats dir
					File statsDir = new File(cmd.getOptionValue("db"));
					if (!statsDir.exists() || (statsDir.exists() && !statsDir.isDirectory()))
						throw new ParseException("Stats directory " + statsDir + " does not exist or is not a directory");
					
					CliOptions.statsDir = statsDir;
				}
			}
			
			// process lib|app arguments, either list of individual files or directory with files
			targetFiles = new ArrayList<File>();
			String fileExt = CliOptions.isMatchingMode? "apk" : "jar"; 

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
			
			if (targetFiles.isEmpty())
				throw new ParseException("You have to provide at least one library to be processed");
			
		} catch (ParseException e) {
			System.err.println("Command line parsing failed:\n" + e.getMessage());
			usage();
		} catch (Exception e) {
			System.err.println("Error occured during argument processing:\n" + e.getMessage());
		}
	}
	
	
	@SuppressWarnings("static-access")
	private static Options setupOptions() {
		options = new Options();
		
		options.addOption(OptionBuilder.withArgName("file")
			.hasArgs(1)
            .isRequired(true)
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
			.hasArgs(1)
	        .isRequired(false)
	        .withLongOpt("profiles-dir")
	        .withDescription("path to store the generated library profiles, defaults to \"./profiles\"")
	        .create("p"));

		options.addOption(OptionBuilder.withArgName("directory")
			.hasOptionalArgs(1)
	        .isRequired(false)
	        .withLongOpt("create-stats-db")
	        .withDescription("generate a stats.db from the generated app stats files")
	        .create("db"));

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
		formatter.printHelp(USAGE, options);
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
