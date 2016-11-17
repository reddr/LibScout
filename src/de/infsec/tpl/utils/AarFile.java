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

import java.io.File;
import java.io.IOException;
import java.util.jar.JarFile;
import java.util.zip.ZipEntry;
import java.util.zip.ZipException;

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

	public AarFile(File file) throws ZipException, IOException {
		super(file);
	}
	
	public AarFile(String fileName) throws ZipException, IOException {
		super(fileName);
	}

	public ZipEntry getClassesJar() {
		return this.getEntry(CLASSES_JAR);
	}
}
