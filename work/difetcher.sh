#!/bin/bash

#rtc change set parse tool
#for man page please refer to below url:
#

me=`basename $0`

srcdir=`pwd`
destdir=`pwd`
verbose=false

#workspace='xianwu_hpc_gui_PCM4_2_0_Gold_Patch_Workspace'
workspace=''

#baseline='pcmdev_PCM4_2_0_0_SNAPSHOT'
baseline=''

#component='pcmdev'
component=''

#when you issued scm login -r 'repourl' -u 'username' -P 'password' -n nickname
#you will get a rtc nickname, with it, you can access jazz server WITHOUT login again!!!
#nickname='leo'
nickname=''

fulldiff=''

#verbose echo 
vecho()
{
    msg="$@"
    if [ "x$verbose" == "xtrue" ]; then
        echo $msg
    fi
}
#get rtc whole diff against a base line

getrtcdiff()
{

    fulldiff="$srcdir/$component.diff"

    vecho "processing full diff for $component: $workspace $baseline from $nickname"
    scm diff -r $nickname  -c "$component" workspace "$workspace" baseline "$baseline" > $fulldiff

    if [ $? != 0 ]; then
        echo "can not get full diff for $component: $workspace $baseline from $nickname"
        exit 1
    fi
}

parsefiles()
{
    diffdir=$1
    destdir=$2
    [ -d "$destdir" ] || mkdir -p "$destdir"
    if [ "x$?" != "x0" ]; then
        echo "can not create dest dir" 1>&2
        exit -1
    fi
    #echo $diffdir
    for diff in  `ls -I $me $diffdir`;
    do 
        # ignore directories, only parse files
        diffpath="$diffdir/$diff"

        [ -d $diffpath ] && continue

        vecho "processing diff: $diff"

        filelistdir="$destdir/$diff.fl"

        rm -fr $filelistdir
        mkdir -p $filelistdir

        #newfilelist=$filelistdir/new.list
        #changedfilelist=$filelistdir/changed.list

        deletefilelist=$filelistdir/delete.list
        filelist=$filelistdir/file.list

        for diffentry in `grep -a "^diff" $diffpath |awk -F " " '{printf "%s;%s\n",$4,$5}'`; 
        do 
            #echo entry: $diffentry
            oldifs=$IFS
            IFS=";"
            filearray=($diffentry)
            IFS=$oldifs
            origfile=${filearray[0]}
            newfile=${filearray[1]}

            #echo "origfile: $origfile"
            #echo "newfile: $newfile"
            
            #not test this line
            if [ "x$newfile" == "x/dev/null" ]; then
                echo "$origfile" >> $deletefilelist
                continue
            fi

            echo "$newfile" >> $filelist

            #if [ "x$origfile" == "x/dev/null" ]; then
            #    echo "$newfile" >> $newfilelist 
            #else
            #    echo "$newfile" >> $changedfilelist
            #fi
        done
    done
}

parseargs()
{
    ARGS=`getopt -a -o s:b:c:n:w:d:hv -l srcdir:,baseline:,component:,workspace:,nickname:,destdir:,help,verbose -- "$@"`
    eval set -- "${ARGS}"
    while true
    do
        case "$1" in
            -n|--nickname)
                nickname=$2
                shift
                ;;
            -c|--component)
                component=$2
                shift
                ;;
            -b|--baseline)
                baseline=$2
                shift
                ;;
            -w|--workspace)
                workspace=$2
                shift
                ;;
            -s|--srcdir)
                srcdir=$2
                shift
                ;;
            -d|--destdir)
                destdir=$2
                shift
                ;;
            -v|--verbose)
                verbose=true
                ;;
            -h|--help)
                usage
                ;;
            --)
                shift
                break
                ;;
        esac
        shift
    done

    if [ "x$nickname" == "x" ]; then
        if [ "x$NICKNAME" == "x" ]; then
            echo "nick name can not be null" 1>&2
            usage
            exit -1
        else
            nickname=$NICKNAME
        fi
    fi

    if [ "x$workspace" == "x" ]; then
        if [ "x$WORKSPACE" == "x" ]; then
            echo "work space can not be null" 1>&2
            usage
            exit -1
        else
            workspace="$WORKSPACE"
        fi
    fi

    if [ "x$baseline" == "x" ]; then
        if [ "x$baseline" == "x" ]; then
            echo "baseline can not be null" 1>&2
            usage
            exit -1
        else
            baseline="$baseline"
        fi
    fi

    if [ "x$component" == "x" ]; then
        if [ "x$component" == "x" ]; then
            echo "component can not be null" 1>&2
            usage
            exit -1
        else
            component="$COMPONENT"
        fi
    fi
}

uniqresult()
{
    destdir=$1

    vecho "processing file list"
    olddir=`pwd`

    cd "$destdir"
    sets=`ls -d *.fl`
    for file in `find $sets -type f`;
    do
        sortedfile=$file.new
        cat $file |uniq |sort > $sortedfile
        mv $sortedfile $file
    done
    cd $olddir
    vecho "done"
}

usage()
{
    cat << _EOF
usage: changesetparser.sh  [-s | -srcdir ] srcdir [ -d | --destdir ] destdir  [ -w | --workspace ] workspace  [ -n | --nickname ] rtc-workspace-nickname [ -c | --component ] component

options:
-s/--srcdir <dirname> directory to store diff file, if this option is not specified, the tool will sore diff in current directory
-d/--destdir <dirname>: directory to store change/add/delete file list, if this option is not specified, the tool will store file list in current directory
-w/--workspace workspace: remote workspace name
-b/--baseline baseline: the baseline to which the spicified workspace is compared to 
-c/--component component: which component to make comparason
-n/--nickname: the nickname of rtc workspace
-v/--verbose: show detail process
-h/--help: show help

environments:
COMPONENT:if -c/--component is not specified, the tool will check the environment variable, and if the variable does not exist or is NULL, the tool will exist
WORKSPACE:if -w/--workspace is not specified, the tool will check the environment variable, and if the variable does not exist or is NULL, the tool will exist
BASELINE: if -b/--baseline is not specified, the tool will check the environment variable, and if the variable does not exist or is NULL, the tool will exist
NICKNAME: if -n/--nickname is not specified, the tool will check the environments variable, and if the variable does not exist or is NULL, the tool will exist

example:
./${me} -b pcmdev_PCM4_2_0_0_SNAPSHOT  -w xianwu_pcmdev_PCM4_2_0_Gold_Patch_Workspace -c pcmdev -n leo
_EOF
    exit 0
}

main()
{
    parseargs $@
    #echo $verbose
    #echo $srcdir $destdir

    getrtcdiff

    parsefiles "$srcdir" "$destdir"
    uniqresult "$destdir"

    exit 0
}

#main entry
main $@
