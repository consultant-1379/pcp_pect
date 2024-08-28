#!/bin/bash

if [ "$2" == "" ]; then
	echo usage: $0 \<Module\> \<Branch\> \<Workspace\>
    	exit -1
else
	versionProperties=install/version.properties
	theDate=\#$(date +"%c")
	module=$1
	branch=$2
	workspace=$3
	BUILD_USER_ID=$4
    REASON=$6
    CT="/usr/atria/bin/cleartool"
	pkgDir=$PWD/packages
	rpmFileLocation=$PWD/pect/target/rpm/ERICpcp-pect-CXC1735783/RPMS/x86_64
	pkgReleaseArea=/home/$USER/eniq_events_releases  # $USER can be jkadm100 or eejkadm

fi

function getReason {
        if [ -n "$REASON" ]; then
        	REASON=`echo $REASON | sed 's/$\ /x/'`
            REASON=`echo JIRA:::$REASON | sed s/" "/,JIRA:::/g`
        else
            REASON="CI-DEV"
        fi
}

function getProductNumber {
        product=`cat $PWD/build.cfg | grep $module | grep $branch | awk -F " " '{print $3}'`
}

function getSprint {
        sprint=`cat $PWD/build.cfg | grep $module | grep $branch | awk -F " " '{print $5}'`
}


function setRstate {

        revision=`cat $PWD/build.cfg | grep $module | grep $branch | awk -F " " '{print $4}'`

        if git tag | grep $product-$revision; then
            build_num=`git tag | grep $revision | wc -l`

            if [ "${build_num}" -lt 10 ]; then
				build_num=0$build_num
			fi
			rstate=`echo $revision$build_num | perl -nle 'sub nxt{$_=shift;$l=length$_;sprintf"%0${l}d",++$_}print $1.nxt($2) if/^(.*?)(\d+$)/';`
		else
            ammendment_level=01
            rstate=$revision$ammendment_level
        fi
        echo "Building R-State:$rstate"

}


function cleanup {
        if [ -d $pkgDir ] ; then
          echo "removing $pkgDir"
          rm -rf $pkgDir
        fi
}

function createTar {
  echo "Copying $rpmFile into $pkgDir"
  cp $rpmFile $pkgDir
  cd $PWD
  tar -czvf $PWD/$pkgName packages/
  echo "Copying tar file into $pkgReleaseArea"
  cp $PWD/$pkgName $pkgReleaseArea
}


function runMaven {
    echo "Running command: mvn -f $PWD/pom.xml clean package -DskipTests=true -Drstate=$rstate"
    mvn -X -f $PWD/pom.xml clean package -DskipTests=true -Drstate=$rstate
    rsp=$?
}


cleanup
getSprint
getProductNumber
setRstate
getReason
echo "Building rstate:$rstate"
pkgName="pcp_pect_${rstate}.tar.gz"

git clean -df
git checkout $branch
git pull

runMaven

mkdir $pkgDir

if [ $rsp == 0 ]; then
  git tag $product-$rstate
  git pull
  git push --tag origin $branch

  rpm=`ls $rpmFileLocation`
  echo "RPM built:$rpm"
  rpmFile=$rpmFileLocation/$rpm
  echo "Creating tar file..."
  createTar
  touch $PWD/rstate.txt
  echo $rstate >> $PWD/rstate.txt
else
  echo "Maven ran with errors!"
  exit -1
fi

if "${Deliver}"; then
    if [ "${DELIVERY_TYPE}" = "SPRINT" ]; then
    $CT setview -exec "/proj/eiffel013_config/fem101/jenkins_home/bin/lxb /vobs/dm_eniq/tools/scripts/deliver_eniq -auto events ${sprint} ${REASON} Y ${BUILD_USER_ID} ${product} NONE $pkgReleaseArea/$pkgName" deliver_ui
else
    $CT setview -exec "/proj/eiffel013_config/fem101/jenkins_home/bin/lxb /vobs/dm_eniq/tools/scripts/eu_deliver_eniq -EU events ${sprint} ${REASON} Y ${BUILD_USER_ID} ${product} NONE $pkgReleaseArea/$pkgName" deliver_ui
    fi
else
   echo "The delivery option was not selected.."
    fi


exit $rsp
