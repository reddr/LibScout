#!/usr/bin/python
#
# Scraper for libraries hosted at jcenter / mvn central / custom maven repos
# Retrieves jar|aar files along with some meta data
#
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
from retrying import retry



## functions ##

def unix2Date(unixTime):
    unixTime = int(str(unixTime)[:-3])
    return datetime.datetime.fromtimestamp(unixTime).strftime('%d.%m.%Y')


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
        desc.write("    <!-- optional: date (format: dd.MM.yyyy  example: 21.05.2017) -->\n")
        desc.write("    <releasedate>{}</releasedate>\n".format(date))
        desc.write("\n")
        desc.write("    <!-- optional: comment -->\n")
        desc.write("    <comment>{}</comment>\n".format(comment))
        desc.write("</library>\n")


@retry(urllib2.URLError, tries=3, delay=3, backoff=1)
def urlopen_with_retry(URL):
    return urllib2.urlopen(URL)


def downloadLibFile(targetDir, repo, groupid, artefactid, version, filetype):
    make_sure_path_exists(os.path.dirname(targetDir + "/"))

    # assemble download URL
    artefactid_r = artefactid.replace(".","/")
    groupid_r = groupid.replace(".","/")

    if repo == MVN_CENTRAL:
        repoURL = "http://search.maven.org/remotecontent?filepath="
        fileName = artefactid_r + "-" + version + "." + filetype

    else:
        repoURL = repo
        fileName = artefactid + "-" + version + "." + filetype

    # retrieve and save file
    URL = repoURL + groupid_r + "/" + artefactid_r + "/" + version + "/" + fileName
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



## library updating routine for mvn central
def updateLibraryMvnCentral(libName, category, comment,  groupId, artefactId):
    # replace all blanks with dash
    libName = libName.replace(" ", "-")
    print "  # check library " + libName + " [" + category + "]   (g:\"" + groupId + "\" AND a:\"" + artefactId + "\")"

    baseDirName = localRepoDir + category + "/" + libName + "/"
    dir = os.path.dirname(baseDirName)
    make_sure_path_exists(dir);

    # Assemble mvn central search URL and retrieve meta data
    try:
        mvnSearchURL = "http://search.maven.org/solrsearch/select?q=g:%22" + groupId + "%22+AND+a:%22" + artefactId + "%22&rows=100&core=gav"
        response = urllib2.urlopen(mvnSearchURL)
        data = json.loads(response.read())
    except urllib2.URLError, e:
        print 'URLError = ' + str(e.reason)
        return
    except Exception, excp:
        print 'Could not retrieve meta data for ' + libName + '  [SKIP]  (' + str(excp) + ')'
        return

    # DEBUG: pretty print json
    #print json.dumps(data, indent=4, sort_keys=True)
    #print

    numberOfVersions = data["response"]["numFound"]
    print "    - retrieved meta data for " + str(numberOfVersions) + " versions:"

    numberOfUpdates = 0
    if numberOfVersions > 0:
        for version in data["response"]["docs"]:

            if skipAlphaBeta and any(x in version["v"].lower() for x in SKIP_KEYWORDS):
                continue;

            # skip lib version if already existing
            if not os.path.isfile(baseDirName + "/" + version["v"] + "/" + LIB_DESCRIPTOR_FILE_NAME):
                numberOfUpdates += 1
                date = unix2Date(version["timestamp"])
                targetDir = baseDirName + version["v"]
                print  "       - update version: {}   type: {}  date: {}  target-dir: {}".format(version["v"], version["p"], date, targetDir)

                result = downloadLibFile(targetDir, MVN_CENTRAL, groupId, artefactId, version["v"], "aar")

                if result == 1:
                    result = downloadLibFile(targetDir, MVN_CENTRAL, groupId, artefactId, version["v"], "jar")

                if result == 0:
                    # write lib description
                    fileName = targetDir + "/" + LIB_DESCRIPTOR_FILE_NAME
                    write_library_description(fileName, libName, category, version["v"], date, comment)


    if numberOfUpdates == 0:
        print "      -> all versions up-to-date"




## library updating routine for jcenter + custom mvn repos
def updateLibrary(libName, category, comment, repoURL, groupId, artefactId):
    # replace all blanks with dash
    libName = libName.replace(" ", "-")
    print "  # check library " + libName + " [" + category + "]   (g:\"" + groupId + "\" AND a:\"" + artefactId + "\")"

    baseDirName = localRepoDir + category + "/" + libName + "/"
    dir = os.path.dirname(baseDirName)
    make_sure_path_exists(dir);

    # Assemble base URL and retrieve meta data
    try:
        if repoURL == "jcenter":
            repoURL = JCENTER_URL

        if not repoURL.endswith("/"):
            repoURL = repoURL + "/"

        metaURL = repoURL + groupId.replace(".","/") + "/" + artefactId.replace(".","/") + "/maven-metadata.xml"

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
            if not skipAlphaBeta or (skipAlphaBeta and not any(x in v.text.lower() for x in SKIP_KEYWORDS)):
                versions.append(v.text)

    numberOfVersions = len(versions)
    print "    - retrieved meta data for " + str(numberOfVersions) + " versions:"

    numberOfUpdates = 0
    if numberOfVersions > 0:
        for version in versions:
            # skip lib version if already existing
            if not os.path.isfile(baseDirName + "/" + version + "/" + LIB_DESCRIPTOR_FILE_NAME):
                numberOfUpdates += 1
                targetDir = baseDirName + version

                fileType = "aar"
                result = downloadLibFile(targetDir, repoURL, groupId, artefactId, version, fileType)

                if result == 1:
                    fileType = "jar"
                    result = downloadLibFile(targetDir, repoURL, groupId, artefactId, version, fileType)

                if result == 0:
                    print  "       - update version: {}   type: {}  date: {}  target-dir: {}".format(version, fileType, "n/a", targetDir)
                    fileName = targetDir + "/" + LIB_DESCRIPTOR_FILE_NAME
                    write_library_description(fileName, libName, category, version, "", comment)


    if numberOfUpdates == 0:
        print "      -> all versions up-to-date"




##  Main functionality ##

LIB_DESCRIPTOR_FILE_NAME = "library.xml"

JCENTER = "jcenter"
JCENTER_URL = "http://jcenter.bintray.com"

MVN_CENTRAL = "mvn-central"

SKIP_KEYWORDS = ['-alpha', '-prealpha', '-beta', '-rc', '-dev', '-snapshot']
skipAlphaBeta = True                    # skip alpha and beta versions

localRepoDir = "my-lib-repo/"           # the directory to store libraries on disk with trailing path separator, e.g. "/"


print "== maven/jcenter scraper =="

# Requires one argument (path to json file with library descriptions)
args = len(sys.argv)
if args != 2:
    print "Usage: " + sys.argv[0] + "  <libraries.json>"
    sys.exit(1)
else:
    inputFile = sys.argv[1]
    print "- Load library info from " + sys.argv[1]

print "- Store libs to " + localRepoDir

# load library definitions
with open(inputFile) as ifile:
    data = json.load(ifile)

# update each lib
print "- Update libraries" + (" (skip alpha/beta versions)" if skipAlphaBeta else "") + ":"
for lib in data["libraries"]:
    if 'repo' not in lib:
        print "[WARN] Skip library: " + lib["name"] + "  (No repo defined!)"
        continue

    elif lib['repo'] == MVN_CENTRAL:
        updateLibraryMvnCentral(lib["name"], lib["category"], lib["comment"], lib["groupid"], lib["artefactid"])

    else:  # jcenter or custom mvn repo URL
        updateLibrary(lib["name"], lib["category"], lib["comment"], lib['repo'], lib["groupid"], lib["artefactid"])

