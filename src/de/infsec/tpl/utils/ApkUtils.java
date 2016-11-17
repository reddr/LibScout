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

package de.infsec.tpl.utils;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipException;
import java.util.zip.ZipFile;
import java.util.zip.ZipInputStream;

public class ApkUtils {
	public static boolean isMultiDexApk(File apkFile) throws ZipException, IOException {
		ZipFile f = new ZipFile(apkFile);
		boolean hasClasses2Dex = f.getEntry("classes2.dex") != null;
		f.close();
		return hasClasses2Dex;		
	}
	
	
	public static Set<ZipEntry> getClassesDex(File apkFile) throws ZipException, IOException {
		HashSet<ZipEntry> result = new HashSet<ZipEntry>();
		ZipFile f = new ZipFile(apkFile);
		
	    final Enumeration<? extends ZipEntry> entries = f.entries();
	    while (entries.hasMoreElements()) {
	        final ZipEntry entry = entries.nextElement();
	        if (entry.getName().matches("classes[1-9]{0,1}\\.dex"))
	        	result.add(entry);
	    }
	    
	    // TODO: unzip those entries to tmp dir and return set<Files>

	    f.close();
	    return result;
	}
	
	

    /**
     * Extracts a zip file specified by the zipFilePath to a directory specified by
     * destDirectory (will be created if does not exists)
     * @param apkFile
     * @param tmpDir
     * @throws IOException
     */
    public static List<File> unzipDexFiles(File apkFile, File tmpDir) throws IOException {
        if (!tmpDir.exists()) {
            tmpDir.mkdir();
        }
        ZipInputStream zipIn = new ZipInputStream(new FileInputStream(apkFile));
        ZipEntry entry = zipIn.getNextEntry();
        
        // iterates over entries in the apk file
        List<File> dexFiles = new ArrayList<File>();
        while (entry != null) {
            File out = new File(tmpDir + File.separator + entry.getName());
            if (!entry.isDirectory()) {
    	        // match classes*.dex
            	if (entry.getName().matches("classes[1-9]{0,1}\\.dex")) {
    	        	extractFile(zipIn, out);
    	        	dexFiles.add(out);
    	        }
            }

            zipIn.closeEntry();
            entry = zipIn.getNextEntry();
        }

        zipIn.close();
        return dexFiles;
    }
    
    
    public static long getSizeOfClassesDex(File apkFile, boolean uncompressedSize) {
 	   ZipFile apkZipFile = null; 
 	   try {
             apkZipFile = new ZipFile(apkFile.getAbsolutePath());
             Enumeration<? extends ZipEntry> zipEntries = apkZipFile.entries();
  
             while (zipEntries.hasMoreElements()) {
             	ZipEntry zipEntry = (ZipEntry) zipEntries.nextElement();
                 if (zipEntry.getName().equals("classes.dex"))
                 	return uncompressedSize? zipEntry.getSize() : zipEntry.getCompressedSize();
             }
         } catch (IOException ex) {
             ex.printStackTrace();
         } finally {
         	if (apkZipFile != null)
 				try {
 					apkZipFile.close();
 				} catch (IOException e) {}
         }
         return -1;
     }
    
    
    /**
     * Extracts a zip entry (file entry)
     * @param zipIn
     * @param outFile
     * @throws IOException
     */
    private static final int BUFFER_SIZE = 4096;
    private static void extractFile(ZipInputStream zipIn, File outFile) throws IOException {
        BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(outFile));
        byte[] bytesIn = new byte[BUFFER_SIZE];
        
        int read = 0;
        while ((read = zipIn.read(bytesIn)) != -1) {
            bos.write(bytesIn, 0, read);
        }
        
        bos.close();
    }
    
}
