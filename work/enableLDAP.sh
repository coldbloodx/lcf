#!/bin/sh
 
# Copyright IBM 2014 
# This tool is used to enable LDAP for PCM and install LDAP client on PCM MN.
# Define following environment variables could run this command in silent mode
## PCM_LDAP_SERVER_URL=
## PCM_LDAP_BASE_DOMAIN=
## PCM_LDAP_BINDDN=
## PCM_LDAP_BINDPW=
## PCM_LDAP_ENABLE_LOGIN_MN=

_DATE=`date +%Y%m%d`
_TIME=`date +%H%M%S`
_HOST=`hostname`
PCM_LDAPSSL=false
CERTS=""

cafile=""
certfile=""
keyfile=""

PCM_KEY_TOOL=/opt/pcm/jre/bin/keytool
if [ ! -f $PCM_KEY_TOOL ]; then
    PCM_KEY_TOOL=`which keytool 2>/dev/null`
fi

PCMD_LOG=${PCM_ROOT}/pcmd/log/pcmd.log
INSTALL_LOG="/tmp/enableLDAP-${_HOST}-${_DATE}-${_TIME}.log"
LDAP_PAM_AUTH="/etc/pam.d/pcmd"
SECURITY_CONF="/etc/security/access.conf"
PCMD_CONFIG_BEGIN_FLAG="#PCM LDAP configuration section: begin"
PCMD_CONFIG_END_FLAG="#PCM LDAP configuration section: end"
# Entitlement file
PCM_ENTITLEMENT_FILE="/opt/pcm/entitlement/pcm.entitlement"
# RHEL pam files
LDAP_PAM_AUTH_PASSWORD_FILE_NAME="password-auth-pcmd"
LDAP_PAM_AUTH_PASSWORD="/etc/pam.d/$LDAP_PAM_AUTH_PASSWORD_FILE_NAME"
# SLES pam files
SLES_LDAP_SESSION_FILE_NAME="common-session-pc-pcmd"
SLES_LDAP_PASSWORD_FILE_NAME="common-password-pc-pcmd"
SLES_LDAP_AUTH_FILE_NAME="common-auth-pc-pcmd"
SLES_LDAP_ACCOUNT_FILE_NAME="common-account-pc-pcmd"


UNKNOWOS="Unsupported Linux Distribution"

_CP="/bin/cp"


# Product Name.
PRODUCTNAME=none
if [ -f "/etc/pcm-release" ]; then
  PRODUCTNAME="IBM Platform Cluster Manager"
elif [ -f "/etc/redhat-release" ]; then
  PRODUCTNAME="IBM Platform HPC"
fi
 
log()
{
   echo "$@" | tee -a $INSTALL_LOG
}

logerr()
{
   echo "Error: $@" | tee -a $INSTALL_LOG
}

trim()
{
    echo $@ | sed 's/[[:space:]]*$//'
}


check_pcm_services()
{
    pcmdstatus=`pcmdadmin list | grep pcmd | awk '{print $2}'`
    if [ "$pcmdstatus" == "STARTED" ] ; then
        log "The PCMD service is still running. Shut down it through 'pcmadmin service stop --service PCMD' before continuing."
        return 1
    fi

    guistatus=`egosh service list -r $_HOST| grep WEBGUI | awk '{print $2}'`
    if [ "$guistatus" == "STARTED" ] ; then
        log "The WEBGUI service is still running. Shut down it through 'pcmadmin service stop --service WEBGUI' before continuing."
        return 1
    fi

    return 0
}

getValueFromXML()
{
    local FilePath=$1
    local keyName=$2
    cat $FilePath | grep "Parameter name=\"$keyName\"" | awk -F ">" '{print $2}' | awk -F "<" '{print $1}'
}

#-----------------------------------------
# Name: prepareInstallLDAP
# Synopsis: prepareInstallLDAP
# Environment Variables:
#       PCM_LDAP_SERVER_URL              mandatory
#       PCM_LDAP_BINDDN                  mandatory
#       PCM_LDAP_BINDPW                  mandatory
#       PCM_LDAP_BASE_DOMAIN             mandatory
#       PCM_LDAP_ENABLE_LOGIN_MN         mandatory
# Description:
#    This function prepares the variables for installing and configuring LDAP client
# Parameters:
#    None
# Return Value:
#    0 successful  1 error
#------------------------------------------------
prepareInstallLDAP()
{
    # check if root user is running this script
    RUNNER=`id | sed -e 's/[^(]*(\([^)]*\)).*/\1/'`
    if [ "$RUNNER" != "root" ]; then
        echo "Root access is required to run this script. Exiting the installation ..."
        exit 1
    fi
   
    if [ x"$PCM_ROOT" = "x" ]; then
        echo -e "The system could not detect $PRODUCTNAME. \nSource the $PRODUCTNAME environment by running \"source PCM_INSTALL_ROOT/bin/pcmenv.sh\"."
        return 1
    fi

    INSTALL_LOG="$PCM_ROOT/log/enableLDAP-${_HOST}-${_DATE}-${_TIME}.log"

    # Check whether pcmd and GUI is running or not.
    check_pcm_services
    if [ "$?" != "0" ]; then
        return 1
    fi

    until [ "$TEST_LDAP_CLIENT" = "success" ]; do
        connectToExistingLDAPServer
        exit_code=$?
        if [ "$exit_code" = "0" ]; then
            TEST_LDAP_CLIENT="success"
        elif [ "$exit_code" = "1" ]; then
            TEST_LDAP_CLIENT="failure"
            return 1
        elif [ "$exit_code" = "2" -a "$PCM_SILENT_INSTALL" != "Y" ]; then
            PCM_LDAP_SERVER_URL=""
            PCM_LDAP_BASE_DOMAIN=""
            PCM_LDAP_BINDDN=""
            PCM_LDAP_BINDPW=""
            PCM_LDAP_ENABLE_LOGIN_MN=""
            inputParaAgain=""
            until [ x"$inputParaAgain" = "xy" -o x"$inputParaAgain" = "xn" ]; do
                echo ""
                echo -n "Input the parameters and try again? (Y/N) [Y]: "
                read inputParaAgain
                if [ x"$inputParaAgain" = "x" ]; then
                    inputParaAgain="y"
                fi
                inputParaAgain=`echo $inputParaAgain|tr '[A-Z]' '[a-z]'`
            done
            if [ x"$inputParaAgain" = "xn" ]; then
                echo -e "\nThe system could not install the LDAP client. Exiting the installation ..."
                TEST_LDAP_CLIENT="failure"
                return 2
            fi
        fi
    done
    
    ISF_MAPPING_USERPW=$PCM_LDAP_BINDPW
}


connectToExistingLDAPServer()
{
    #Set LDAP server URL 
    msg="Type the URL of the LDAP server (for example, ldap://LDAP_server:389): \c"
    until [ x"$PCM_LDAP_SERVER_URL" != "x" ]; do
        if [ "$PCM_SILENT_INSTALL" == "Y" ]; then
            logerr "PCM_LDAP_SERVER_URL is null in silent mode"
            return 1
        fi
        echo -e $msg
        read PCM_LDAP_SERVER_URL
        PCM_LDAP_SERVER_URL=`trim ${PCM_LDAP_SERVER_URL}`
    done
    until [ "$VALID_LDAP_SERVER_URL" = "yes" ]; do
        # Check server URL
        regex=^ldaps?://[^:]+\(:[0-9]+\)?$
        if [[ $PCM_LDAP_SERVER_URL =~ $regex ]]; then
            VALID_LDAP_SERVER_URL="yes"
        else
            VALID_LDAP_SERVER_URL="no"
            logerr "Invalid server URL: "$PCM_LDAP_SERVER_URL
            if [ "$PCM_SILENT_INSTALL" == "Y" ]; then
                return 1
            fi
            echo -e $msg
            read PCM_LDAP_SERVER_URL
        fi

        # check whether ldap enabled ssl
        regex=^ldaps://.*$
        if [[ $PCM_LDAP_SERVER_URL =~ $regex ]]; then
            PCM_LDAPSSL=true
        fi
    done
    
    if [ "x$PCM_LDAPSSL" = "xtrue" ]; then
        msg="Type the CA certificate file, certificate file and private key, like:/root/ca.pem;/root/client.cert;/root/client.key"
        until [ x"$CERTS" != "x" ]; do
            if [ "$PCM_SILENT_INSTALL" == "Y" ]; then
                logerr "CERTS is null in silent mode"
                return 1
            fi
            echo -e $msg
            read CERTS
            CERTS=`trim ${CERTS}`
        done

        validcert=no
        until [ "$validcert" = "yes" ]; do
            # Check certs
            oldifs=$IFS
            IFS=";"
            certarray=($CERTS)
            IFS=$oldifs

            if [ "x${#certarray[*]}" != "x3" ]; then
                echo "file count is not correct"
                continue
            fi
           
            # check certs one by one
            flag=true
            for cert in ${certarray[@]}; do
                if [ ! -f $cert ]; then
                    echo $cert does NOT exist
                    flag=false
                    break
                fi
            done

            if [ "x$flag" != "xtrue" ]; then
                echo -e $msg
                read CERTS 
            else
                validcert=yes
            fi
        done
        cafile=${certarray[0]}
        certfile=${certarray[1]}
        keyfile=${certarray[2]}
    fi

    #Set LDAP base Domain
    msg="Type the base domain where users and groups will be retrieved (for example, dc=example,dc=com): \c"
    until [ x"$PCM_LDAP_BASE_DOMAIN" != "x" ]; do
        if [ "$PCM_SILENT_INSTALL" == "Y" ]; then
            logerr "PCM_LDAP_BASE_DOMAIN is null in silent mode"
            return 1
        fi
        echo -e $msg
        read PCM_LDAP_BASE_DOMAIN
        PCM_LDAP_BASE_DOMAIN=`trim ${PCM_LDAP_BASE_DOMAIN}`
    done
    until [ "$VALID_LDAP_BASE_DOMAIN"  = "yes" ]; do
        DCs=`echo $PCM_LDAP_BASE_DOMAIN | awk -F ',' '{print $0}' | sed "s/,/ /g"`
        for dc in $DCs; do
            #Check domain name
            regex=^dc\=[a-zA-Z0-9]\([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9]\)$
            if [[ $dc =~ $regex ]]; then
                VALID_LDAP_BASE_DOMAIN="yes"
            else
                VALID_LDAP_BASE_DOMAIN="no"
                logerr "Invalid base domain: "$dc
                if [ "$PCM_SILENT_INSTALL" == "Y" ]; then
                    return 1
                fi
                echo -e $msg
                read PCM_LDAP_BASE_DOMAIN
                break
            fi
        done
    done

    msg="Type the distinguished name of the LDAP user mapped to $PRODUCTNAME (for example, uid=pcmuser,ou=user,$PCM_LDAP_BASE_DOMAIN): \c"
    until [ x"$PCM_LDAP_BINDDN" != "x" ]; do
        if [ "$PCM_SILENT_INSTALL" == "Y" ]; then
            logerr "PCM_LDAP_BINDDN is null in configuration file"
            return 1
        fi
        echo -e $msg
        read PCM_LDAP_BINDDN
        PCM_LDAP_BINDDN=`trim ${PCM_LDAP_BINDDN}`
    done
    until [ "$VALID_LDAP_BINDDN" = "yes" ]; do
        #Check domain name
        regex=$PCM_LDAP_BASE_DOMAIN$
        if [[ $PCM_LDAP_BINDDN =~ $regex ]]; then
            VALID_LDAP_BINDDN="yes"
        else
            VALID_LDAP_BINDDN="no"
            logerr "Invalid distinguished name: "$PCM_LDAP_BINDDN
            if [ "$PCM_SILENT_INSTALL" == "Y" ]; then
                return 1
            fi
            echo -e $msg
            read PCM_LDAP_BINDDN
            PCM_LDAP_BINDDN=`trim ${PCM_LDAP_BINDDN}`
        fi
    done
    
    until [ x"$PCM_LDAP_BINDPW" != "x" ]; do
        if [ "$PCM_SILENT_INSTALL" == "Y" ]; then
            logerr "PCM_LDAP_BINDPW is null in configuration file"
            return 1
        fi
        stty -echo
        echo -n "Type the password for the mapped user: "
        read PCM_LDAP_BINDPW
        stty echo
        echo ""
    done

    msg="Enable base domain LDAP users login this node through SSH? (Y/N) [N]"
    until [ x"$PCM_LDAP_ENABLE_LOGIN_MN" = "xy" -o x"$PCM_LDAP_ENABLE_LOGIN_MN" = "xn" ]; do
        if [ "$PCM_SILENT_INSTALL" == "Y" ]; then
            logerr "PCM_LDAP_ENABLE_LOGIN_MN is null in configuration file"
            return 1
        fi
        echo -e $msg
        read PCM_LDAP_ENABLE_LOGIN_MN
        tmpldapflag=$PCM_LDAP_ENABLE_LOGIN_MN
        PCM_LDAP_ENABLE_LOGIN_MN=`trim ${PCM_LDAP_ENABLE_LOGIN_MN}`
        PCM_LDAP_ENABLE_LOGIN_MN=`echo $PCM_LDAP_ENABLE_LOGIN_MN | tr '[A-Z]' '[a-z]'`
        if [ x"$PCM_LDAP_ENABLE_LOGIN_MN" == "x" ]; then
            PCM_LDAP_ENABLE_LOGIN_MN="n"
        fi
        if [ x"$PCM_LDAP_ENABLE_LOGIN_MN" != "xy" -a x"$PCM_LDAP_ENABLE_LOGIN_MN" != "xn" ]; then
            logerr "Invalid parameter: $tmpldapflag"
        fi
    done
    
    log "Verifying LDAP configuration..."
    log ""

    #Install ldap client package
    pkgs=''
    if [ x$OSTYPE = xrhel ]; then
        pkgs="openldap openldap-clients"
    elif [ x$OSTYPE = xsles ]; then
        pkgs="openldap2-client"
    elif [ x$OSTYPE = xubuntu ]; then
        pkgs="ldap-utils"
    fi
    installpkgs $pkgs

    # validate ldap connection
    if [ "x$PCM_LDAPSSL" == "xtrue" ]; then
        mv /etc/openldap/ldap.conf /etc/openldap/ldap.conf.orig
        echo "TLS_REQCERT allow" > /etc/openldap/ldap.conf
    fi

    ldapsearch -x -b $PCM_LDAP_BASE_DOMAIN -D $PCM_LDAP_BINDDN -H $PCM_LDAP_SERVER_URL -w $PCM_LDAP_BINDPW -z 1 &> /dev/null

    if [ "$?" != "0" -a "$?" != "4" ]; then
        log "The system could not connect to the LDAP server. Verify your input parameters."
        if [ "$PCM_SILENT_INSTALL" == "Y" ]; then
            return 1
        fi
        return 2
    fi
    
    # validate bindDN
    _BINDDN=`ldapsearch -x -b $PCM_LDAP_BASE_DOMAIN -D $PCM_LDAP_BINDDN -H $PCM_LDAP_SERVER_URL -w $PCM_LDAP_BINDPW | grep -i "dn: $PCM_LDAP_BINDDN"`
    ISF_MAPPING_USERNAME=`echo $_BINDDN|awk -F ',' '{print $1}'|awk -F '=' '{print $2}'`
    
    # Parse LDAP SERVER HOST
    LDAPSERVERNAME=`echo $PCM_LDAP_SERVER_URL | awk -F '://' '{print $2}'`
    
    # move configuration file back
    if [ "x$PCM_LDAPSSL" == "xtrue" ]; then
        mv /etc/openldap/ldap.conf.orig /etc/openldap/ldap.conf 
        rm -f /etc/openldap/ldap.conf.orig

        mkdir -p /etc/openldap/{cacerts,certs}
        
        cp -fr $cafile /etc/openldap/cacerts/
        cafile="/etc/openldap/cacerts/`basename $cafile`"
        
        cp -fr $certfile $keyfile /etc/openldap/certs
        certfile="/etc/openldap/certs/`basename $certfile`"
        keyfile="/etc/openldap/certs/`basename $keyfile`"
    fi
}


function update_or_append_config()
{
    local _option=$1
    local _filename=$2
    local _option_name=`echo $_option | cut -d= -f1`
    local _option_value=`echo $_option | cut -d= -f2`

    local _exists=`grep $_option_name $_filename`

    if [ ! -z "$_exists" ]; then
        sed -e 's/'$_option_name'=.*/'$_option_name'='$_option_value'/' < $_filename > $_filename.bak
        mv $_filename.bak $_filename
    else
        echo "$_option_name=$_option_value" >> $_filename
    fi

    return 0
}

function configure_pcmd()
{
    log "Configuring pcmd..."
    log ""

    PCMDCONFIG=${PCM_ROOT}/pcmd/conf/pcmdConfig.xml
    # Create following parameters in pcmdConfig.xml
    #     <Parameter name="userDir.enabled">true</Parameter>
    #     <Parameter name="userDir.type">LDAP</Parameter>
    #     <Parameter name="userDir.ssl">false</Parameter>
    grep -q "<Parameter name=\"userDir\.ssl\">"  $PCMDCONFIG
    if [ "$?" = "0" ]; then
        sed -i "s/\(<Parameter name=\"userDir.ssl\">\).*/\1$PCM_LDAPSSL<\/Parameter>/g" $PCMDCONFIG
    else
        sed -i "/<\/pcmdConfigData>/ i\    <Parameter name=\"userDir.ssl\">$PCM_LDAPSSL<\/Parameter>" $PCMDCONFIG
    fi

    grep -q "<Parameter name=\"userDir\.enabled\">"  $PCMDCONFIG
    if [ "$?" = "0" ]; then
        sed -i "s/\(<Parameter name=\"userDir.enabled\">\).*/\1true<\/Parameter>/g" $PCMDCONFIG
    else
        sed -i "/<\/pcmdConfigData>/ i\    <Parameter name=\"userDir.enabled\">true<\/Parameter>" $PCMDCONFIG
    fi

    grep -q "<Parameter name=\"userDir\.type\">"  $PCMDCONFIG
    if [ "$?" = "0" ]; then
        sed -i "s/\(<Parameter name=\"userDir.type\">\).*/\1LDAP<\/Parameter>/g" $PCMDCONFIG
    else
        sed -i "/<\/pcmdConfigData>/ i\    <Parameter name=\"userDir.type\">LDAP<\/Parameter>" $PCMDCONFIG
    fi

    grep -q "<Parameter name=\"userDir\.dirContext\">"  $PCMDCONFIG
    if [ "$?" = "0" ]; then
        sed -i "s/\(<Parameter name=\"userDir.dirContext\">\).*/\1ldap<\/Parameter>/g" $PCMDCONFIG
    else
        sed -i "/<\/pcmdConfigData>/ i\    <Parameter name=\"userDir.dirContext\">ldap<\/Parameter>" $PCMDCONFIG
    fi
    
    grep -q "<Parameter name=\"userDir\.providerURL\">"  $PCMDCONFIG
    if [ "$?" = "0" ]; then
        #get ldap server port
        ip=`echo $LDAPSERVERNAME| awk -F ":" '{print $1}'`
        port=`echo $LDAPSERVERNAME| awk -F ":" '{print $2}'`

        proto="ldap"
        if [ "x$PCM_LDAPSSL" == "xtrue" ]; then
            proto="ldaps"
            [ "x$port" = "x" ] && port="636"
        else
            [ "x$port" = "x" ] && port="389"
        fi

        sed -i "s/\(<Parameter name=\"userDir.providerURL\">\).*/\1$proto:\/\/$ip:$port<\/Parameter>/g" $PCMDCONFIG
    else
        sed -i "/<\/pcmdConfigData>/ i\    <Parameter name=\"userDir.providerURL\">$PCM_LDAP_SERVER_URL<\/Parameter>" $PCMDCONFIG
    fi
    
    grep -q "<Parameter name=\"userDir\.securityPrincipal\">"  $PCMDCONFIG
    if [ "$?" = "0" ]; then
        sed -i "s/\(<Parameter name=\"userDir.securityPrincipal\">\).*/\1$PCM_LDAP_BINDDN<\/Parameter>/g" $PCMDCONFIG
    else
        sed -i "/<\/pcmdConfigData>/ i\    <Parameter name=\"userDir.securityPrincipal\">$PCM_LDAP_BINDDN<\/Parameter>" $PCMDCONFIG
    fi
    
    grep -q "<Parameter name=\"userDir\.securityCredential\">"  $PCMDCONFIG
    if [ "$?" = "0" ]; then
        sed -i "s/\(<Parameter name=\"userDir.securityCredential\">\).*/\1$PCM_LDAP_BINDPW<\/Parameter>/g" $PCMDCONFIG
    else
        sed -i "/<\/pcmdConfigData>/ i\    <Parameter name=\"userDir.securityCredential\">$PCM_LDAP_BINDPW<\/Parameter>" $PCMDCONFIG
    fi
    
    grep -q "<Parameter name=\"userDir\.defaultBase\">"  $PCMDCONFIG
    if [ "$?" = "0" ]; then
        sed -i "s/\(<Parameter name=\"userDir.defaultBase\">\).*/\1$PCM_LDAP_BASE_DOMAIN<\/Parameter>/g" $PCMDCONFIG
    else
        sed -i "/<\/pcmdConfigData>/ i\    <Parameter name=\"userDir.defaultBase\">$PCM_LDAP_BASE_DOMAIN<\/Parameter>" $PCMDCONFIG
    fi
    
    grep -q "<Parameter name=\"userDir\.searchScope\">"  $PCMDCONFIG
    if [ "$?" = "0" ]; then
        sed -i "s/\(<Parameter name=\"userDir.searchScope\">\).*/\1subtree<\/Parameter>/g" $PCMDCONFIG
    else
        sed -i "/<\/pcmdConfigData>/ i\    <Parameter name=\"userDir.searchScope\">subtree<\/Parameter>" $PCMDCONFIG
    fi
    
    grep -q "<Parameter name=\"userDir\.updateIntervalSec\">"  $PCMDCONFIG
    if [ "$?" = "0" ]; then
        sed -i "s/\(<Parameter name=\"userDir.updateIntervalSec\">\).*/\130<\/Parameter>/g" $PCMDCONFIG
    else
        sed -i "/<\/pcmdConfigData>/ i\    <Parameter name=\"userDir.updateIntervalSec\">30<\/Parameter>" $PCMDCONFIG
    fi
    
    grep -q "<Parameter name=\"userDir\.cacheEnable\">"  $PCMDCONFIG
    if [ "$?" = "0" ]; then
        sed -i "s/\(<Parameter name=\"userDir.cacheEnable\">\).*/\1true<\/Parameter>/g" $PCMDCONFIG
    else
        sed -i "/<\/pcmdConfigData>/ i\    <Parameter name=\"userDir.cacheEnable\">true<\/Parameter>" $PCMDCONFIG
    fi
    
    PCMAUTHCONFIG=${PCM_ROOT}/pcmd/conf/auth/pamauth.conf
    # update auth config.
    grep -q "^PAM_SERVICE="  $PCMAUTHCONFIG
    if [ "$?" = "0" ]; then
        sed -i "s/\(PAM_SERVICE=\).*/\1pcmd/g" $PCMAUTHCONFIG
    else
        echo "PAM_SERVICE=pcmd" >> $PCMAUTHCONFIG
    fi
}

installAndConfigLDAPClient()
{
    case $OSTYPE in
        rhel)
            installAndConfigLDAPClientOnRHEL
            ;;
        sles)
            installAndConfigLDAPClientOnSLES
            ;;
        ubuntu)
            installAndConfigLDAPClientOnUbuntu
            ;;
    esac
}

installAndConfigLDAPClientOnUbuntu()
{
    log "Installing LDAP client required packages..."
    log ""

    pamconfdir=/etc/pam.d
    localpamconf=/etc/.pcmlocal
    if [ ! -d $localpamconf ]; then
        mkdir  $localpamconf
        cp $pamconfdir/common-* $localpamconf
    fi

    installpkgs ldap-auth-config nscd
    ldappamconf=/etc/.pcmldap
    if [ ! -d $ldappamconf ]; then
        mkdir $ldappamconf
        cp $pamconfdir/common-* $ldappamconf
    fi

    bakfiles "/etc/ldap.conf /etc/nsswitch.conf"


    # create ldap.conf
    cat > /etc/ldap.conf <<_EOF
base $PCM_LDAP_BASE_DOMAIN
binddn $PCM_LDAP_BINDDN
uri $PCM_LDAP_SERVER_URL
bindpw $PCM_LDAP_BINDPW
ldap_version 3
_EOF

    # update /etc/nsswitch
    nsfile=/etc/nsswitch.conf
    order="ldap files"
    sed -i "s/^passwd:.*/passwd: $order/g; s/^group:.*/group: $order/g; s/^shadow:.*/shadow: $order/g" $nsfile

    service nscd restart > /dev/null 2>&1

    if [ "x$PCM_LDAP_ENABLE_LOGIN_MN" == "xn" ]; then
        cp $localpamconf/common-* $pamconfdir/
    else
        cp $ldappamconf/common-* $pamconfdir
    fi
}

bakfiles()
{
    array=($1)
    for file in ${array[@]};
    do
        \cp -fr $file $file.bak
    done
}

installAndConfigLDAPClientOnRHEL()
{
    log "Installing LDAP client required packages..."
    log ""

    installpkgs pam_ldap nss-pam-ldapd authconfig

    # check the version of openldap-clients
    local openldap_ver=`rpm -qa openldap-clients* | cut -d- -f3- | cut -d. -f1-2`
    local openldap_major_ver=`echo $openldap_ver | cut -d. -f1`
    local openldap_minor_ver=`echo $openldap_ver | cut -d. -f2`
    
    if [ "$openldap_major_ver" == "2" -a \
         "$openldap_minor_ver" == "3" ]; then
        # in OpenLDAP 2.3, there's only one ldap config file
        configs="/etc/ldap.conf"
    else
        configs="/etc/pam_ldap.conf /etc/nslcd.conf"
    fi

    for config in $configs; do
        grep -q "^binddn" $config
        if [ "$?" = "0" ]; then
            sed -i "s/^\(binddn\).*/\1 $PCM_LDAP_BINDDN/g" $config
        else
            echo "binddn $PCM_LDAP_BINDDN" >> $config
        fi

        grep -q "^bindpw" $config
        if [ "$?" = "0" ]; then
            sed -i "s/^\(bindpw\).*/\1 $PCM_LDAP_BINDPW/g" $config
        else
            echo "bindpw $PCM_LDAP_BINDPW" >> $config
        fi

        uaconf $config "tls_reqcert" "never"
    done
    
    if [ "x$PCM_LDAPSSL" == "xtrue" ]; then
        update_certsconfig
        genkeystore
    fi
    
    #disable sssd
    local authconfig_major_ver=`rpm -qa authconfig | cut -d- -f2- | cut -d. -f1`
    if [ "$authconfig_major_ver" == "5" ]; then
        # authconfig 5 (RHEL 5.x) doesn't have enableforcelegacy.  add this
        # manually to /etc/sysconfig/authconfig
        update_or_append_config FORCELEGACY=yes /etc/sysconfig/authconfig
        /usr/sbin/authconfig --disablesssd --disablesssdauth --update >> $INSTALL_LOG
    else
        /usr/sbin/authconfig --disablesssd --disablesssdauth --enableforcelegacy --update >> $INSTALL_LOG
    fi
    if [ "$?" != "0" ]; then
        log "The system could not disable SSSD service using the authconfig commands."
        return 1
    fi
    
    #Config LDAP client files
    /usr/sbin/authconfig --enableldap --enableldapauth --ldapserver=$PCM_LDAP_SERVER_URL --ldapbasedn=$PCM_LDAP_BASE_DOMAIN --update >> $INSTALL_LOG
    if [ "$?" != "0" ] ; then
        log "The system could not configure the LDAP client using the authconfig command."
        return 1
    fi
    $_CP -f /etc/pam.d/sshd $LDAP_PAM_AUTH
    sed -i -e "s/password-auth/$LDAP_PAM_AUTH_PASSWORD_FILE_NAME/g" $LDAP_PAM_AUTH

    # Allow root to access and block all other OS users.
    sed -i '2iauth    required        pam_access.so   debug' $LDAP_PAM_AUTH
    sed -i '/^- : ALL EXCEPT root : ALL/d' $SECURITY_CONF
    # get all local users.
    otherusers=`cat /etc/passwd | awk -F ':' '{if ($3 > 500 ) {print $1}}'`
    grep -q "$PCMD_CONFIG_BEGIN_FLAG" $SECURITY_CONF
    if [ "$?" = "0" ]; then
        sed -i "/$PCMD_CONFIG_BEGIN_FLAG/,/$PCMD_CONFIG_END_FLAG/d" $SECURITY_CONF
    fi
    echo $PCMD_CONFIG_BEGIN_FLAG >> $SECURITY_CONF
    for otheruser in $otherusers
    do
        if [ -f /etc/phpc-release -a "$otheruser" == "phpcadmin" ]; then
            echo "+ : $otheruser : ALL" >> $SECURITY_CONF
        else
            echo "- : $otheruser : ALL" >> $SECURITY_CONF
        fi
    done
    echo "+ : root : ALL" >> $SECURITY_CONF
    echo $PCMD_CONFIG_END_FLAG >> $SECURITY_CONF
    
    $_CP -f /etc/pam.d/password-auth $LDAP_PAM_AUTH_PASSWORD

    #rollback the pam default password-auth
    if [ x$PCM_LDAP_ENABLE_LOGIN_MN = "xn" ]; then
        /usr/sbin/authconfig --disableldapauth --disableldaptls --update >> $INSTALL_LOG
        if [ "$?" != "0" ]; then
            log "The system could not disable LDAPTLS services using the authconfig commands."
            return 1
        fi
    fi

    # Restart LDAP client service, if nss-pam-ldapd rpm is present
    local _nslcd_service=`rpm -qa nss-pam-ldapd`
    if [ ! -z "$_nslcd_service" ]; then
        service nslcd restart >> $INSTALL_LOG
        if [ "$?" != "0" ]; then
            log "The system could not restart the LDAP client service and could not configure the LDAP client."
            return 1
        fi
    fi
}

#should be update_or_append_conf
#for short, make it uaconf
uaconf()
{
    local conf=$1
    local key=$2
    local value=$3
    grep -qi "^$key"  $conf
    if [ $? == 0 ]; then
        sed -i "s#^\($key\).*#\1 $value#Ig" $conf 
    else
        echo "$key $value" >>  $conf
    fi
}

update_certsconfig()
{
    conf=/etc/openldap/ldap.conf
    uaconf $conf "tls_reqcert" "never"
    uaconf $conf "tls_cacertfile" "$cafile"
    uaconf $conf "tls_certfile" "$certfile"
    uaconf $conf "tls_keyfile" "$keyfile"
}

genkeystore()
{
    keytool -import -file $cafile -alias ldapca  -keystore /root/.xcat/keystore.ldap -storepass letmein -noprompt > /dev/null
    keytool -import -file $certfile -alias ldappubcert -keystore /root/.xcat/keystore.ldap -storepass letmein -noprompt > /dev/null
}

installAndConfigLDAPClientOnSLES()
{
    log "Installing LDAP client required packages..."
    log ""

    installpkgs pam_ldap nss_ldap  pam_ldap-32bit nss_ldap-32bit openldap2-client

    config=/etc/ldap.conf
    grep -q "^binddn" $config
    if [ "$?" = "0" ]; then
        sed -i "s/^\(binddn\).*/\1 $PCM_LDAP_BINDDN/g" $config
    else
        echo "binddn $PCM_LDAP_BINDDN" >> $config
    fi

    grep -q "^bindpw" $config
    if [ "$?" = "0" ]; then
        sed -i "s/^\(bindpw\).*/\1 $PCM_LDAP_BINDPW/g" $config
    else
        echo "bindpw $PCM_LDAP_BINDPW" >> $config
    fi

    /sbin/yast ldap pam enable server="$LDAPSERVERNAME" base="$PCM_LDAP_BASE_DOMAIN" ldappw="$PCM_LDAP_BINDPW" sssd=no tls=no
        if [ "$?" != "0" ] ; then
        log "The system could not configure the LDAP client using the authconfig command."
        return 1
    fi

    #set certs, keys path.
    if [ "x$PCM_LDAPSSL" == "xtrue" ]; then
        update_certsconfig
        genkeystore
    fi

    $_CP -f /etc/pam.d/common-session-pc /etc/pam.d/$SLES_LDAP_SESSION_FILE_NAME
    $_CP -f /etc/pam.d/common-password-pc /etc/pam.d/$SLES_LDAP_PASSWORD_FILE_NAME
    $_CP -f /etc/pam.d/common-auth-pc /etc/pam.d/$SLES_LDAP_AUTH_FILE_NAME
    $_CP -f /etc/pam.d/common-account-pc /etc/pam.d/$SLES_LDAP_ACCOUNT_FILE_NAME

    $_CP -f /etc/pam.d/sshd $LDAP_PAM_AUTH
    sed -i -e "s/common-session/$SLES_LDAP_SESSION_FILE_NAME/g" $LDAP_PAM_AUTH
    sed -i -e "s/common-password/$SLES_LDAP_PASSWORD_FILE_NAME/g" $LDAP_PAM_AUTH
    sed -i -e "s/common-auth/$SLES_LDAP_AUTH_FILE_NAME/g" $LDAP_PAM_AUTH
    sed -i -e "s/common-account/$SLES_LDAP_ACCOUNT_FILE_NAME/g" $LDAP_PAM_AUTH
    
    # Allow root to access and block all other OS users.
    sed -i '2iauth    required        pam_access.so   debug' $LDAP_PAM_AUTH
    sed -i '/^- : ALL EXCEPT root : ALL/d' $SECURITY_CONF
    # get all local users.
    otherusers=`cat /etc/passwd | awk -F ':' '{if ($3 > 500 ) {print $1}}'`
    grep -q "$PCMD_CONFIG_BEGIN_FLAG" $SECURITY_CONF
    if [ "$?" = "0" ]; then
        sed -i "/$PCMD_CONFIG_BEGIN_FLAG/,/$PCMD_CONFIG_END_FLAG/d" $SECURITY_CONF
    fi
    echo $PCMD_CONFIG_BEGIN_FLAG >> $SECURITY_CONF
    for otheruser in $otherusers
    do
        if [ -f /etc/phpc-release -a "$otheruser" == "phpcadmin" ]; then
            echo "+ : $otheruser : ALL" >> $SECURITY_CONF
        else
            echo "- : $otheruser : ALL" >> $SECURITY_CONF
        fi
    done
    echo "+ : root : ALL" >> $SECURITY_CONF
    echo $PCMD_CONFIG_END_FLAG >> $SECURITY_CONF

    #rollback the pam default password-auth
    if [ x$PCM_LDAP_ENABLE_LOGIN_MN = "xn" ]; then
        sed -i -e '/pam_ldap.so/d' /etc/pam.d/common-session-pc 
        sed -i -e '/pam_ldap.so/d' /etc/pam.d/common-password-pc
        sed -i -e '/pam_ldap.so/d' /etc/pam.d/common-auth-pc
        sed -i -e '/pam_ldap.so/d' /etc/pam.d/common-account-pc
        
        if [ "$?" != "0" ]; then
            log "The system could not disable LDAP services using the yast commands."
            return 1
        fi
    else
        log "Updating nsswitch.conf..."
        grep "^passwd\:" /etc/nsswitch.conf  > /dev/null 2>&1
        if [ "$?" = "0" ]; then
            sed -i -e "s/^passwd\:.*/passwd: files ldap/g" /etc/nsswitch.conf
        else
            echo "passwd: files ldap" >>  /etc/nsswitch.conf
        fi
    fi

    # Restart LDAP client service
    if [ -f /etc/init.d/nscd ]; then
        /etc/init.d/nscd restart >> $INSTALL_LOG
        if [ "$?" != "0" ]; then
            log "The system could not restart the LDAP client service and could not configure the LDAP client."
            return 1
        fi
    fi

}

enable_cn_ldap()
{
    log "Enable LDAP client setup for compute nodes..."
    log ""

    chdef -t site LDAP_ENABLEFLAG=true  > /dev/null 2>&1
    chdef -t site LDAP_SERVER_URL=$PCM_LDAP_SERVER_URL  > /dev/null 2>&1 
    chdef -t site LDAP_BASE_DOMAIN=$PCM_LDAP_BASE_DOMAIN  > /dev/null 2>&1
    chdef -t site LDAP_BIND_USER=$PCM_LDAP_BINDDN  > /dev/null 2>&1
    chdef -t site LDAP_BIND_USERPW=$PCM_LDAP_BINDPW  > /dev/null 2>&1
    chdef -t site LDAP_SSLFLAG=$PCM_LDAPSSL > /dev/null 2>&1
}

exiton_install()
{
    trap '' $TRAP_SIGNAL
    log ""
    log "Installation interrupted. Removing installed files."
    exit $TRAP_EXIT_CODE
}

getostype()
{
    case `lsb_release -is` in
        Ubuntu*)
            echo "ubuntu"
            ;;
        RedHat*)
            echo "rhel"
            ;;
        SUSE*)
            echo "sles"
            ;;
        *)
            echo "$UNKNOWOS" 2>&1
            exit 1
    esac
}

installpkgs()
{
    installcmd=''
    pkgmgrname=''
    errmsg="Verify that %s is configured correctly. Exiting the installation ...\n"
    case $OSTYPE in
        rhel)
            installcmd="yum -y install "
            pkgmgrname=yum
            ;;

        sles)
            installcmd="zypper install -y --auto-agree-with-licenses "
            pkgmgrname=zypper
            ;;
        ubuntu)
            installcmd="DEBIAN_FRONTEND=noninteractive apt-get -y install "
            pkgmgrname=apt
            ;;
        *)
            echo $UNKNOWOS 2>&1
            exit 1
    esac
    installcmd="$installcmd $@ >> $INSTALL_LOG 2>&1"
    echo $installcmd >> $INSTALL_LOG
    eval $installcmd
    if [ "x$?" != "x0" ]; then
        printf "$errmsg" $pkgmgrname 2>&1
        exit 1
    fi
}

#======================Main Entry===========================
# OS type:
OSTYPE=`getostype`

TRAP_SIGNAL="1 2 3 15"
TRAP_EXIT_CODE=99
trap exiton_install $TRAP_SIGNAL

if [ "$1" == "-s" -o "$1" == "--standby" ]; then
    _RUN_ON_STANDBY="Y"
fi

prepareInstallLDAP
if [ "$?" != "0" ]; then
    exit 1
fi

installAndConfigLDAPClient
if [ "$?" != "0" ]; then
    exit 1
fi

# Enable LDAP flag for PCMD
configure_pcmd

# Enable LDAP setup for SE CNs
enable_cn_ldap

log ""
log "$PRODUCTNAME has been successfully configured to retrieve user information from LDAP."
log "Logs can be found in $PCMD_LOG"

# To config on failover node, quit without additional messages.
if [ "x$_RUN_ON_STANDBY" == "xY" ]; then
    exit 0
fi

log "Start up PCMD service by running 'pcmadmin service start --service PCMD'"
log "Start up WEBGUI service by running 'pcmadmin service start --service WEBGUI'"

# Check if advance edition
grep ^PCM_Advanced $PCM_ENTITLEMENT_FILE > /dev/null 2>&1
if [ "$?" != "0" ]; then
    exit 0
fi

log ""
log "To enable LDAP settings, ensure that all existing cluster templates are unpublished and then published again."
log "Next, in order for LDAP users to access existing clusters, all existing clusters must be removed, and then created again."

exit 0

