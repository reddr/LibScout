#!/usr/bin/python
#
# Scraper for libraries hosted at jcenter and custom maven repos
# Retrieves jar|aar files along with some meta data
# @author erik derr [derr@cs.uni-saarland.de]
#

import sys
import json
import urllib2
import datetime
import os
import errno
import zipfile
import traceback
import xml.etree.ElementTree as ElementTree
from retrying import retry  # may require "pip install retrying"


## functions ##

def make_sure_path_exists(path):
    try:
        os.makedirs(path)
    except OSError as exception:
        if exception.errno != errno.EEXIST:
            raise


def write_library_description(fileName, libName, category, version, date, comment):
    make_sure_path_exists(os.path.dirname(fileName))

    # write lib description in xml format
    with open(fileName, "w") as desc:
        desc.write("<?xml version=\"1.0\"?>\n")
        desc.write("<library>\n")
        desc.write("    <!-- library name -->\n")
        desc.write("    <name>{}</name>\n".format(libName))
        desc.write("\n")
        desc.write("    <!-- Advertising, Analytics, Android, SocialMedia, Cloud, Utilities -->\n")
        desc.write("    <category>{}</category>\n".format(category))
        desc.write("\n")
        desc.write("    <!-- optional: version string -->\n")
        desc.write("    <version>{}</version>\n".format(version))
        desc.write("\n")
        desc.write("    <!-- optional: date (format: DD/MM/YYYY) -->\n")
        desc.write("    <releasedate>{}</releasedate>\n".format(date))
        desc.write("\n")
        desc.write("    <!-- optional: comment -->\n")
        desc.write("    <comment>{}</comment>\n".format(comment))
        desc.write("</library>\n")


@retry(urllib2.URLError, tries=3, delay=3, backoff=1)
def urlopen_with_retry(URL):
    return urllib2.urlopen(URL)


def downloadFile(targetDir, repoURL, groupid, artefactid, version, filetype):
    make_sure_path_exists(os.path.dirname(targetDir + "/"))

    # assemble download URL
    fileName = artefactid + "-" + version + "." + filetype
    URL = repoURL + "/" + groupid.replace(".","/") + "/" + artefactid.replace(".","/") + "/" + version + "/" + fileName

    # retrieve and save file
    targetFile = targetDir + "/" + fileName

    try:
        libFile = urllib2.urlopen(URL)
        with open(targetFile,'wb') as output:
            output.write(libFile.read())

        return 0
    except urllib2.HTTPError, e:
        if filetype != 'aar':
            print '    !! HTTP Error while retrieving ' + filetype + ' file:  ' + str(e.code)
        return 1
    except urllib2.URLError, e:
        print '    !! URL Error while retrieving ' + filetype + ' file: ' + str(e.reason)
        return 1
    except Exception, excp:
        print '    !! Download failed: ' + str(excp)
        return 1




def updateLibrary(libName, category, comment, repoURL, groupId, artefactId):
    # replace all blanks with dash
    libName = libName.replace(" ", "-")
    print "  # check library " + libName + " [" + category + "]   (g:\"" + groupId + "\" AND a:\"" + artefactId + "\")"

    baseDirName = rootDir + category + "/" + libName + "/"
    dir = os.path.dirname(baseDirName)
    make_sure_path_exists(dir);

    # Assemble base URL and retrieve meta data
    try:
        mvnURL = repoURL + "/" + groupId.replace(".","/") + "/" + artefactId.replace(".","/")
        metaURL = mvnURL + "/maven-metadata.xml"

        response = urllib2.urlopen(metaURL)
        data = response.read()
        response.close()
    except urllib2.URLError, e:
        print 'URLError = ' + str(e.reason)
        return
    except Exception, excp:
        print 'Could not retrieve meta data for ' + libName + '  [SKIP]  (' + str(excp) + ')'
        return

    # retrieve available versions
    versions = []
    root = ElementTree.fromstring(data)
    for vg in root.find('versioning'):
        for v in vg.iter('version'):
            if not skipAlphaBeta or (skipAlphaBeta and not '-alpha' in v.text and not '-beta' in v.text and not '-rc' in v.text and not '-dev' in v.text): 
                versions.append(v.text)

    numberOfVersions = len(versions)
    print "    - retrieved meta data for " + str(numberOfVersions) + " versions:"

    numberOfUpdates = 0
    if numberOfVersions > 0:
        for version in versions:
            # skip lib version if already existing
            if not os.path.isfile(baseDirName + "/" + version + "/" + libDescriptorFileName):
                numberOfUpdates += 1
                targetDir = baseDirName + version
                print  "       - update version: {}   type: {}  date: {}  target-dir: {}".format(version, "aar/jar", "n/a", targetDir)

                result = downloadFile(targetDir, repoURL, groupId, artefactId, version, "aar")

                if result == 1:
                    result = downloadFile(targetDir, repoURL, groupId, artefactId, version, "jar")

                if result == 0:
                    # write lib description
                    fileName = targetDir + "/" + "library.xml"
                    write_library_description(fileName, libName, category, version, "", comment)


    if numberOfUpdates == 0:
        print "      -> all versions up-to-date"




##  Main functionality ##

inputFile = "glibs.json"
libDescriptorFileName = "library.xml"
rootDir = "my-mvn-repo/"
skipAlphaBeta = True  # skip alpha and beta versions

print "== maven/jcenter scraper =="

# Requires one argument (path to json file with library descriptions)
args = len(sys.argv)
if args != 2:
    print "Usage: " + sys.argv[0] + "  <libraries.json>"
    sys.exit(1)
else:
    inputFile = sys.argv[1]
    print "Load libraries from " + sys.argv[1]


# load iterate over lib json
with open(inputFile) as ifile:
    data = json.load(ifile)

# update each lib
for lib in data["libraries"]:
    if 'repo' not in lib:
        repoURL = "http://jcenter.bintray.com"
    else:
        repoURL = lib['repo']   # custom maven

    updateLibrary(lib["name"], lib["category"], lib["comment"], repoURL, lib["groupid"], lib["artefactid"])
