#
#  Copyright (c) 2015-2016  Erik Derr [derr@cs.uni-saarland.de]
#
#  Licensed under the Apache License, Version 2.0 (the "License"); you may not use this
#  file except in compliance with the License. You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software distributed under
#  the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
#  KIND, either express or implied. See the License for the specific language governing
#  permissions and limitations under the License.
#

#!/usr/bin/python
#
# Crawler for libraries hosted at mvn central
# Retrieves jar|aar files along with some meta data

import json
import urllib2
import datetime
import os
import errno
import zipfile
import traceback
from retrying import retry  # may require "pip install retrying"


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
        desc.write("    <!-- optional: date (format: DD/MM/YYYY) -->\n")
        desc.write("    <releasedate>{}</releasedate>\n".format(date))
        desc.write("\n")
        desc.write("    <!-- optional: comment -->\n")
        desc.write("    <comment>{}</comment>\n".format(comment))
        desc.write("</library>\n")


# TODO: decorator does not work
@retry(urllib2.URLError, tries=3, delay=3, backoff=1)
def urlopen_with_retry(URL):
    return urllib2.urlopen(URL)


def downloadFile(targetDir, groupid, artefactid, version, filetype):
    make_sure_path_exists(os.path.dirname(targetDir + "/"))

    # assemble download URL
    baseURL = "http://search.maven.org/remotecontent?filepath="
    artefactid_r = artefactid.replace(".","/")
    groupid_r = groupid.replace(".","/")
    URL = baseURL + groupid_r + "/" + artefactid_r + "/"

    # sometimes it just returns the type "bundle", we then access the jar file
    if filetype == "bundle":
        filetype = "jar"

    fileName = artefactid_r + "-" + version + "." + filetype
    URL = URL + version + "/" + fileName

    # retrieve and save file
    targetFile = targetDir + "/" + fileName

    try:
        libFile = urllib2.urlopen(URL)
        with open(targetFile,'wb') as output:
            output.write(libFile.read())

        # if filetype is aar unzip classes.jar (since WALA currently does not handle aar's directly)
        if filetype == "aar":
            fh = open(targetFile, 'rb')
            z = zipfile.ZipFile(fh)
            for f in z.namelist():
                if f == "classes.jar":
                    z.extract(f, targetDir)
            fh.close()

        return 0
    except urllib2.HTTPError, e:
        print 'HTTPError = ' + str(e.code)
        return 1
    except urllib2.URLError, e:
        print 'URLError = ' + str(e.reason)
        return 1
    except Exception, excp:
        print 'Download failed  (' + str(excp) + ')'
        return 1




def updateLibrary(libName, category, comment,  groupId, artefactId):
    # replace all blanks with dash
    libName = libName.replace(" ", "-")
    print "  # check library " + libName + " [" + category + "]   (g:\"" + groupId + "\" AND a:\"" + artefactId + "\")"

    baseDirName = rootDir + category + "/" + libName + "/"
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
            # skip lib version if already existing
            if not os.path.isfile(baseDirName + "/" + version["v"] + "/" + libDescriptorFileName):
                numberOfUpdates += 1
                date = unix2Date(version["timestamp"])
                targetDir = baseDirName + version["v"]
                print  "       - update version: {}   type: {}  date: {}  target-dir: {}".format(version["v"], version["p"], date, targetDir)

                result = downloadFile(targetDir, groupId, artefactId, version["v"], version["p"])

                if result == 0:
                    # write lib description
                    fileName = targetDir + "/" + "library.xml"
                    write_library_description(fileName, libName, category, version["v"], date, comment)


    if numberOfUpdates == 0:
        print "      -> all versions up-to-date"




##  Main functionality ##

inputFile = "libraries.json"
libDescriptorFileName = "library.xml"
rootDir = "lib-sdks"  ### change this directory to your lib-sdks dir ###

print "== mvn central crawler =="

# load iterate over lib json
with open(inputFile) as ifile:
    data = json.load(ifile)

# update each lib
for lib in data["libraries"]:
    updateLibrary(lib["name"], lib["category"], lib["comment"], lib["groupid"], lib["artefactid"])

