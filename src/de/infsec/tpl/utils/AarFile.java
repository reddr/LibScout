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

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.jar.JarFile;
import java.util.zip.ZipEntry;
import java.util.zip.ZipException;
import java.util.zip.ZipFile;


/**
 * The 'aar' bundle is the binary distribution of an Android Library Project.
 * The file extension is .aar, and the maven artifact type should be aar as well, but the file itself a simple zip file with the following entries:
 *    - /AndroidManifest.xml (mandatory)
 *    - /classes.jar (mandatory)
 *    - /res/ (mandatory)
 *    - /R.txt (mandatory)
 *    - /assets/ (optional)
 *    - /libs/*.jar (optional)
 *    - /jni/<abi>/*.so (optional)
 *    - /proguard.txt (optional)
 *    - /lint.jar (optional)
 * These entries are directly at the root of the zip file.
 * The R.txt file is the output of aapt with --output-text-symbols.
 */

public class AarFile extends JarFile {
	public static final String CLASSES_JAR = "classes.jar";
	private File jarFile;

	public AarFile(File file) throws ZipException, IOException, ClassNotFoundException {
		super(file);
		this.jarFile = extractClassesJar(file, new File(System.getProperty("java.io.tmpdir")));		
	}
	
	public AarFile(String fileName) throws ZipException, IOException, ClassNotFoundException {
		this(new File(fileName));
	}
	
	public JarFile getJarFile() throws IOException {
		return new JarFile(this.jarFile);
	}
	
	/*
	@Override
	public Enumeration<JarEntry> entries() {
		try (JarFile jf = new JarFile(jarFile)) {
			return jf.entries();
		} catch (IOException e) {}
		
		return Collections.emptyEnumeration();
	}*/
	
	/** 
	 * Extracts a zip file specified by the zipFilePath to a directory specified by
	 * destDirectory (will be created if does not exists)
	 * @param apkFile
	 * @param tmpDir
	 * @throws IOException
	 */  
	public File extractClassesJar(File aarFile, File tmpDir) throws IOException {
		try (ZipFile zip = new ZipFile(aarFile)) {
			ZipEntry entry = zip.getEntry(CLASSES_JAR);	

			if (entry != null) {
				File outDir = new File(tmpDir + File.separator + "jarTmp" + File.separator + aarFile.getName().replace(".aar", ""));
				if (!outDir.exists()) outDir.mkdirs();
				
				File outFile = new File(outDir + File.separator + entry.getName());
				
     			if (!entry.isDirectory()) {
     				extractFile(zip.getInputStream(entry), outFile);
     				return outFile;
		        }   
		    }   
		}
	    	
		throw new IOException("Could not extract classes.jar");
	}   

	    
    /** 
     * Extracts a zip entry (file entry)
     * @param zipIn
     * @param outFile
     * @throws IOException
     */  
    private static final int BUFFER_SIZE = 4096;
    private void extractFile(InputStream in, File outFile) throws IOException {
        BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(outFile));
        byte[] bytesIn = new byte[BUFFER_SIZE];

        int read = 0;
        while ((read = in.read(bytesIn)) != -1) {
            bos.write(bytesIn, 0, read);
        }   

        bos.close();
    }   

}

