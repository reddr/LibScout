#!/bin/bash
#
# Convenience script to generate library profiles with LibScout
# Usage: $0 <library-directory>
#
# In each subdirectory of <library-directory> there must only be one library .jar|.aar file
# with its library.xml description. The mvn scraper scripts automatically create such a file structure, e.g.
# <library-directory>
#    |_OkHttp
#       |_3.0.0
#       |  |_library.xml
#       |  |_okhttp-3.0.0.jar
#       |_3.0.1
#          |_library.xml
#          |_okhttp-3.0.1.jar
#
# ATTENTION:
# Before being able to use this script, you first have to replace the placeholder
# values <NOTSET> for the LibScout root directory and the path to the Android SDK.
#
# The LibScout.jar is automatically being built, if not existing.
# Change $JOBS to run multiple LibScout instances in parallel.
# The profiles are emitted to $LIBSCOUT_ROOT/profiles
#
# @author Erik Derr [derr@cs.uni-saarland.de]
#

# LibScout dir and arguments
LIBSCOUT_ROOT="<NOTSET>"                      # path to the LibScout root directory
LIBSCOUT="$LIBSCOUT_ROOT/build/LibScout.jar"
ANDROID_SDK="<NOTSET>"                        # argument: path to Android SDK

LOG_DIR=""    # optional argument: enable logging via "-d <log_dir>"
JOBS=5        # Number of parallel instances

BUILDSCRIPT="$LIBSCOUT_ROOT/build.xml"
LIBXML="library.xml"


function usage() {
	echo "Usage $0 <library-directory>"
	exit 0
}

function seconds2Time() {
   H=$(($1/60/60%24))
   M=$(($1/60%60))
   S=$(($1%60))

   if [ ${H} != 0 ]; then
      echo ${H} h ${M} min ${S} sec
   elif [ ${M} != 0 ]; then
      echo ${M} min ${S} sec
   else
      echo ${S} sec
   fi
}


## 1. check for <UNSET> variables
if [ $LIBSCOUT_ROOT = "<NOTSET>" ]; then
	echo "Please set the path to LibScout.jar via the \"LIBSCOUT_ROOT\" variable and retry."
	exit 1
fi

if [ $ANDROID_SDK = "<NOTSET>" ]; then
	echo "Please set the path to the Android SDK via the \"ANDROID_SDK\" variable and retry."
	exit 1
fi

## 2. process command line args
if [ $# -gt 1 -o $# -eq 0 ]; then
	usage
elif [ $# -eq 1 ]; then
	LIBDIR=$1
	if [ ! -d $LIBDIR ]; then
		echo "[error] $LIBDIR is not a directory"!
		usage
	fi
fi

# change to libscout root
CUR_DIR=`pwd`
cd $LIBSCOUT_ROOT

## 3. generate LibScout.jar if not existing
if [ ! -e $LIBSCOUT ]; then
	echo -n "[info] $LIBSCOUT does not exist, generating jar file now..."
	ant -f $BUILDSCRIPT build > /dev/null
	if [ $? != 0 ]; then
		echo "[failed]"
		exit $rc;
	fi
	echo "[done]"
fi

## 4. generate library profiles
echo "= Generating library profiles ="
STARTTIME=$(date +%s)

# run $JOBS instances in parallel
echo "# `find $LIBDIR -type f -name $LIBXML| wc -l` library.xml files found in $LIBDIR"
find $LIBDIR -type f -name $LIBXML |  parallel --no-notice --jobs $JOBS "echo \" - gen profile: {//}\" ; java -jar $LIBSCOUT -o profile -m -a $ANDROID_SDK $LOG_DIR -x {} {//}"

ENDTIME=$(date +%s)
echo
echo "# processing done in `seconds2Time $[ $ENDTIME - $STARTTIME ]`"
cd $CUR_DIR  # restore old dir

