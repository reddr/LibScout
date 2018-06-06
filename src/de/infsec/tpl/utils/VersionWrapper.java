package de.infsec.tpl.utils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.github.zafarkhaja.semver.Version;

/**
 * Wrapper Class for {@link Version}
 */
// TODO extends Version?
public class VersionWrapper {
	private static final Logger logger = LoggerFactory.getLogger(de.infsec.tpl.utils.VersionWrapper.class);
	
	public enum SEMVER {
		PATCH ("patch"),
		MINOR ("minor"),
		MAJOR ("major");

		private final String name;

		private SEMVER(String s) {
			name = s;
		}

		public String toString() {
			return this.name;
		}
	}

	
	/**
	 * {@link Version.valueOf} requires a valid x.y.z scheme. This version parser further allows x and x.y schemes
	 * and initializes the missing values with zero. 
	 * @param versionStr
	 * @return
	 */
	public static Version valueOf(String versionStr) {
		if (versionStr.isEmpty()) {
			logger.warn("Empty version string!");
			return null;
		}
		
		String[] version = versionStr.split("\\.");
		
		if (version.length == 1)  { // like 12  is transformed into 12.0.0
			logger.debug("Invalid semVer (minor+patch level missing): " + versionStr);
			return Version.forIntegers(Integer.parseInt(version[0]));
		}
		
		if (version.length == 2)  { // like 7.2  is transformed into 7.2.0
			logger.debug("Invalid semVer (patch level missing): " + versionStr);
			
			// 11.1-rc1 is transformed into 11.1.0-rc1
			if (version[1].indexOf('-') != -1) {
				String[] frag = version[1].split("-");
				
				String ext = "";
				for (int i = 1; i < frag.length; i++)
					ext += "-" + frag[i];
					
				return Version.valueOf(version[0] + "." + frag[0] + ".0" + ext);
			}
						
			return Version.forIntegers(Integer.parseInt(version[0]),Integer.parseInt(version[1]));
		}
		
		if (version.length == 3)   //  like 3.2.1
			return Version.valueOf(versionStr);
		
		if (version.length >= 3) {   // like 5.2.1.3  is transformed into 5.2.1-build3
			logger.debug("Invalid semVer (sub-patch level): " + versionStr);
			Version.Builder builder = new Version.Builder(version[0] + "." + version[1] + "." + version[2]);
			builder.setBuildMetadata("build." + version[3]);
			return builder.build();
		}

		logger.debug("Invalid semVer: " + versionStr);
		return null;
	}
	
	
	/**
	 * Determines change between two versions  
	 * @param versionStr0  first version string
	 * @param versionStr1  second version string
	 * @return  version change, one of ["major", "minor", "patch"] or null if some error occurs
	 */

	// TODO TODO rewrite
	public static String determineVersionChange(String versionStr0, String versionStr1) {
		Version v0 = VersionWrapper.valueOf(versionStr0);
		Version v1 = VersionWrapper.valueOf(versionStr1);
		
		if (v0.getMajorVersion() < v1.getMajorVersion()) {
			return SEMVER.MAJOR.toString();
		} 
		
		else if (v0.getMajorVersion() == v1.getMajorVersion()) {
			
			if (v0.getMinorVersion() < v1.getMinorVersion()) {
				return SEMVER.MINOR.toString();
			} else if (v0.getMinorVersion() == v1.getMinorVersion()) {
				
				if (v0.getPatchVersion() < v1.getPatchVersion()) {
					return SEMVER.PATCH.toString();
				} else if (v0.getPatchVersion() == v1.getPatchVersion()) {
					if (!v1.getBuildMetadata().isEmpty())  // subpatch levels are encoded by build meta data through VersionWrapper
						return SEMVER.PATCH.toString();
				} else
					return null;
			}
		} 

		return null;
	}


	public static SEMVER getExpectedSemver(Version v0, Version v1) {
		if (v0.getMajorVersion() < v1.getMajorVersion()) {
			return SEMVER.MAJOR;
		}

		else if (v0.getMajorVersion() == v1.getMajorVersion()) {

			if (v0.getMinorVersion() < v1.getMinorVersion()) {
				return SEMVER.MINOR;
			} else if (v0.getMinorVersion() == v1.getMinorVersion()) {

				if (v0.getPatchVersion() < v1.getPatchVersion()) {
					return SEMVER.PATCH;
				} else if (v0.getPatchVersion() == v1.getPatchVersion()) {
					if (!v1.getBuildMetadata().isEmpty())  // subpatch levels are encoded by build meta data through VersionWrapper
						return SEMVER.PATCH;
				} else
					return null;
			}
		}

		return null;
	}


	// strip trailling zeros, e.g. 3.4.0 -> 3.4
	public static String getTruncatedVersion(Version v) {
		String vStr = "" + v.getMajorVersion();
		if (v.getMinorVersion() > 0  || (v.getMinorVersion() == 0 && v.getPatchVersion() > 0)) {
			vStr += "." + v.getMinorVersion();

			if (v.getPatchVersion() > 0)
				vStr += "." + v.getPatchVersion();

			if (v.getBuildMetadata().length() > 1)
				vStr += "-" + v.getBuildMetadata();
		}
		return vStr;
	}
}
