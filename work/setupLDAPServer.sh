#!/bin/sh
 
TMP_DIR="/tmp/.inst.tmp$$"
TMP_OS_ISO=${TMP_DIR}/.tmp_os_iso
_DATE=`date +%Y%m%d`
_TIME=`date +%H%M%S`
_HOST=`hostname`
INSTALL_LOG="/tmp/setupLDAPServer-${_HOST}-${_DATE}-${_TIME}.log"
INIT_LDIF_FILE="/tmp/init.ldif"

# ldap related variables
catop=/etc/pki/CA
bakcatop=/etc/pki/CA.orig

keypass="Lemtein"
cnstr="/CN=IBM"

#for ca keys
sslconf=/etc/pki/tls/openssl.cnf
baksslconf=/etc/pki/tls/openssl.cnf.orig
cakey=ca.key
careq=ca.req
cacert=ca.cert

scert=server
ccert=client
 
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

# use yum to install related package
install_package_by_yum(){
    for _pkg in $*; do
        yum -y install $_pkg >> $INSTALL_LOG 2>&1
        if [ "$?" != "0" ];then
            logerr "Yum did not successfully install package $_pkg install."
            return 1
        fi
    done
}

check_ldap_server_required_pkgs(){
    # check if yum is already hooked up and we can install ldap server required packages
    _pkgs="openldap openldap-servers"
    for _pkg in $_pkgs; do
        yum -q list $_pkg &>/dev/null
        if [ "$?" != "0" ]; then
            # we cannot use yum to install this package
            return 1
        fi
    done
    return 0
}

#-----------------------------------------
# Name: prepareInstallLDAP
# Synopsis: prepareInstallLDAP
# Environment Variables:
#    ISO_PATH                     mandatory 
#    ISF_LDAP_BASE_DOMAIN         mandatory
#    ISF_LDAP_ROOT_DN             mandatory
#    ISF_LDAP_ROOT_PW             mandatory
#    ISF_MAPPING_USERNAME         mandatory
#    ISF_MAPPING_USERPW           mandatory
#    ISF_LDAP_BASE_DOMAIN         mandatory
#    ISF_LDAP_ADMIN_SUB_DOMAIN    mandatory
#    ISF_MAPPING_USERNAME         mandatory
#    ISF_MAPPING_USERPW           mandatory   
# Description:
#    This function prepares the variables for installing and configuring LDAP server
# Parameters:
#    None
# Return Value:
#    0 successful  1 error
#------------------------------------------------
prepareInstallLDAP()
{
    checkLDAPInstallEnv
    if [ "$?" != "0" ]; then
        return 1
    fi
    log ""
    prepare_iso
    
    #Set LDAP baseDomain
    
    until [ "$VALID_LDAP_BASE_DOMIN"  = "yes" ]; do
        echo -n "The base domain will be \"dc=example,dc=com\". Press Enter to accept this value, or type a different one: "
        read ISF_LDAP_BASE_DOMAIN
        ISF_LDAP_BASE_DOMAIN=`trim ${ISF_LDAP_BASE_DOMAIN}`
        if [ x"$ISF_LDAP_BASE_DOMAIN" == "x" ]; then
            ISF_LDAP_BASE_DOMAIN="dc=example,dc=com"
        fi
        DCs=`echo $ISF_LDAP_BASE_DOMAIN | awk -F ',' '{print $0}' | sed "s/,/ /g"`
        for dc in $DCs; do
            #Check domain name
            regex=^dc\=[a-zA-Z0-9]\([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9]\)$ 
            if [[ $dc =~ $regex ]]; then
                VALID_LDAP_BASE_DOMIN="yes"
            else
                VALID_LDAP_BASE_DOMIN="no"
                echo "Invalid domain: $dc"
                echo "Tip: Specify a domain name that consists of at least one uppercase or lowercase alphabetic character. It can also contain a dash (-)"
                break
            fi
        done
    done
    
    #Set LDAP rootDN
    until [ "$VALID_LDAP_ROOT_DN" = "yes" ]; do
	    echo -n "The name of the LDAP root distinguished name (rootDN) will be \"Manager\". Press Enter to accept this value, or type a different one: "
	    read ISF_LDAP_ROOT_DN_NAME
	    ISF_LDAP_ROOT_DN_NAME=`trim ${ISF_LDAP_ROOT_DN_NAME}`
	    if [ x"$ISF_LDAP_ROOT_DN_NAME" == "x" ]; then
	        ISF_LDAP_ROOT_DN="cn=Manager,$ISF_LDAP_BASE_DOMAIN"
	    else
	        ISF_LDAP_ROOT_DN="cn=$ISF_LDAP_ROOT_DN_NAME,$ISF_LDAP_BASE_DOMAIN"
	    fi
        #Check domain name
        regex=^cn\=[a-zA-Z0-9]\([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9]\)\,$ISF_LDAP_BASE_DOMAIN$
        if [[ $ISF_LDAP_ROOT_DN =~ $regex ]]; then
            VALID_LDAP_ROOT_DN="yes"
        else
            VALID_LDAP_ROOT_DN="no"
            echo "Invalid root distinguished name (rootDN): $ISF_LDAP_ROOT_DN_NAME"
            echo "Tip: Specify a rootDN name that consists of at least one uppercase or lowercase alphabetic character. It can also contain a dash (-)"
        fi
    done
    
    #Set password for rootDN
    until [ "$ISF_LDAP_ROOT_PW_OK" = "yes" ]; do
        until [ x"$ISF_LDAP_ROOT_PW" != "x" ]; do
            echo -n "Assign a password for the LDAP rootDN: "
            stty -echo
            read ISF_LDAP_ROOT_PW
            stty echo
            echo ""
        done

        until [ x"$ISF_LDAP_ROOT_PW_CFM" != "x" ]; do
            echo -n "Confirm the password: "
            stty -echo
            read ISF_LDAP_ROOT_PW_CFM
            stty echo
            echo ""
        done

        if [ "$ISF_LDAP_ROOT_PW" = "$ISF_LDAP_ROOT_PW_CFM" ]; then
            ISF_LDAP_ROOT_PW_OK="yes"
        else
            ISF_LDAP_ROOT_PW_OK="no"
            ISF_LDAP_ROOT_PW=""
            ISF_LDAP_ROOT_PW_CFM=""
            echo "Warning: Your password and confirmation password do not match. Retype your passwords."
        fi
    done

    until [ "$VALID_ISF_MAPPING_USERNAME"  = "yes" ]; do
	    echo -e "Create an LDAP user to be mapped to Platform Cluster Manager Advanced Edition administrator, default user will be \"Admin\".\nPress Enter to accept this value, or type a different one: \c"
	    read ISF_MAPPING_USERNAME
	    ISF_MAPPING_USERNAME=`trim ${ISF_MAPPING_USERNAME}`
	    if [ x"$ISF_MAPPING_USERNAME" == "x" ]; then
	        ISF_MAPPING_USERNAME="Admin"
	    fi
	    regex=^[a-zA-Z0-9]\([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9]\)$ 
	    if [[ $ISF_MAPPING_USERNAME =~ $regex ]]; then
	        VALID_ISF_MAPPING_USERNAME="yes"
	    else
	        VALID_ISF_MAPPING_USERNAME="no"
	        echo "Invalid user name: $ISF_MAPPING_USERNAME"
	        echo "Tip: Specify a user name that consists of at least one uppercase or lowercase alphabetic character. It can also contain a dash (-)"
	    fi
    done

    #Set password for the mapping user
    echo "The LDAP user \"$ISF_MAPPING_USERNAME\" is mapped to the Platform Cluster Manager Advanced Edition administrator."
    until [ "$ISF_MAPPING_USERPW_OK" = "yes" ]; do
        until [ x"$ISF_MAPPING_USERPW" != "x" ]; do
            echo -n "Assign a password for the mapped user: "
            stty -echo
            read ISF_MAPPING_USERPW
            stty echo
            echo ""
        done

        until [ x"$ISF_MAPPING_USERPW_CFM" != "x" ]; do
            echo -n "Confirm the password: "
            stty -echo
            read ISF_MAPPING_USERPW_CFM
            stty echo
            echo ""
        done

        if [ "$ISF_MAPPING_USERPW" = "$ISF_MAPPING_USERPW_CFM" ]; then
            ISF_MAPPING_USERPW_OK="yes"
        else
            ISF_MAPPING_USERPW_OK="no"
            ISF_MAPPING_USERPW=""
            ISF_MAPPING_USERPW_CFM=""
            echo "Warning: Your password and confirmation password do not match. Retype your passwords."
        fi
    done
    
    #Set LDAP admin sub Domain
    until [ "$VALID_LDAP_ADMIN_SUB_DOMIN"  = "yes" ]; do
	    echo -e "The sub domain directly under the base domain where users and groups can be assigned as Platform Cluster Manager Advanced Edition\nadministrators will be \"admin\". \nPress Enter to accept this value, or type a different one: \c"
	    read ISF_LDAP_ADMIN_SUB_DOMAIN
	    ISF_LDAP_ADMIN_SUB_DOMAIN=`trim ${ISF_LDAP_ADMIN_SUB_DOMAIN}`
	    if [ x"$ISF_LDAP_ADMIN_SUB_DOMAIN" == "x" ]; then
	        ISF_LDAP_ADMIN_SUB_DOMAIN="admin"
	    fi
        DCs=`echo $ISF_LDAP_ADMIN_SUB_DOMAIN | awk -F ',' '{print $0}' | sed "s/,/ /g"`
        #Check domain name
        regex=^[a-zA-Z0-9]\([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9]\)$ 
        if [[ $ISF_LDAP_ADMIN_SUB_DOMAIN =~ $regex ]]; then
            VALID_LDAP_ADMIN_SUB_DOMIN="yes"
        else
            VALID_LDAP_ADMIN_SUB_DOMIN="no"
            echo "Invalid sub domain name: $dc"
            echo "Tip: Specify a sub domain name that consists of at least one uppercase or lowercase alphabetic character. It can also contain a dash (-)"
        fi
    done
    
}

checkLDAPInstallEnv()
{
    # check if root user is running this script
    RUNNER=`id | sed -e 's/[^(]*(\([^)]*\)).*/\1/'`
    if [ "$RUNNER" != "root" ]; then
        echo "Root access is required to run this script. Exiting the installation ..."
        exit 1
    fi

    env_ok=y
    SERVER_PKG=`rpm -qa|grep openldap-servers`	
    if [ "$?" = "0" ]; then
        echo -e "\nThe LDAP server is already installed. Run the following command to uninstall it, and then re-run setupLDAPServer.sh.\nrpm -e $SERVER_PKG"
        env_ok=n
    fi
    LDAP_SERVER_CHECK_FILES="/var/lib/ldap /etc/openldap/slapd.d"
    for F in $LDAP_SERVER_CHECK_FILES; do
        if [ -d $F ]; then
            exist_files="$exist_files $F"
        fi
    done
    if [ x"$exist_files" != "x" ]; then
        echo -e "\nThe LDAP server configuration and database directories $exist_files already exist.\nBack up and remove them, and then re-run setupLDAPServer.sh."
        env_ok=n
    fi
    /etc/init.d/iptables status  &> /dev/null
    if [ "$?" = "0" ]; then
        echo -e "\nWarning: Your firewall is running. Ensure it allows TCP port 389 for LDAP services, or disable your firewall."
    fi
    if [ "$env_ok" == "n" ]; then
        echo ""
        return 1
    fi
}

generateInitLDIF()
{
cat >> $INIT_LDIF_FILE <<EOF
dn: $BASE
objectClass: dcObject
objectClass: Organization
objectClass: top
dc: $BASEDC
o: Corporation
description: LDAP server for IBM

dn: $ADMIN_SUB_DOMAIN,$BASE
objectClass: dcObject
objectClass: Organization
objectClass: top
dc: $ISF_LDAP_ADMIN_SUB_DOMAIN
o: $ISF_LDAP_ADMIN_SUB_DOMAIN

dn: ou=user,$ADMIN_SUB_DOMAIN,$BASE
objectClass: organizationalUnit
objectClass: top
ou: user

dn: ou=group,$ADMIN_SUB_DOMAIN,$BASE
objectClass: organizationalUnit
objectClass: top
ou: group

dn: cn=admin_group,ou=group,$ADMIN_SUB_DOMAIN,$BASE
objectClass: posixGroup
objectClass: top
cn: admin_group
gidNumber: 10000
memberUid: $USERID

dn: uid=$USERID,ou=user,$ADMIN_SUB_DOMAIN,$BASE
objectClass: posixAccount
objectClass: top
objectClass: inetOrgPerson
gidNumber: 10000
sn: $USERID
displayName: $USERID
uid: $USERID
homeDirectory: /home/$USERID
cn: $USERID
uidNumber: 10000
userPassword: $PASSWORD
loginShell: /bin/sh

dn: uid=pcmae_user,$ADMIN_SUB_DOMAIN,$BASE
objectClass: posixAccount
objectClass: top
objectClass: inetOrgPerson
gidNumber: 0
sn: pcmae_user
displayName: pcmae_user
uid: pcmae_user
homeDirectory: /tmp
cn: pcmae_user
uidNumber: 10001
userPassword: $PCMAEPW
loginShell: /bin/sh

EOF
}

installAndConfigLDAPServer()
{
    log ""
    log "Installing the LDAP server ..."
    
    #Install ldap server package
    install_package_by_yum openldap openldap-servers
    if [ $? != 0 ]; then
        log "Verify that yum is configured correctly. Exiting the installation ... "
        return 1
    fi

    # check the version of openldap-servers. in openldap-servers-2.3 
    # we need to generate the dynamic config in cn=config
    local openldap_ver=`rpm -qa openldap-servers* | cut -d- -f3- | cut -d. -f1-2`
    local openldap_major_ver=`echo $openldap_ver | cut -d. -f1`
    local openldap_minor_ver=`echo $openldap_ver | cut -d. -f2`
    
    local service_name="slapd"
    
    if [ "$openldap_major_ver" == "2" -a \
         "$openldap_minor_ver" == "3" ]; then
        sed -e '/^database/ i\
database config \
rootdn "cn=admin,cn=config" \
rootpw config' \
< /etc/openldap/slapd.conf > /etc/openldap/slapd.conf.tmp
        mv /etc/openldap/slapd.conf.tmp /etc/openldap/slapd.conf

        mkdir -p /etc/openldap/slapd.d
        slaptest -f /etc/openldap/slapd.conf -F /etc/openldap/slapd.d >/dev/null 2>&1
        chown -R ldap:ldap /etc/openldap/slapd.d

        # when generating these config files, the db filename is different
        bdb_ldif="/etc/openldap/slapd.d/cn=config/olcDatabase={1}bdb.ldif"
       
        # service name in openldap-2.3 is "ldap" instead of "slapd"
        service_name="ldap"
    else
        bdb_ldif="/etc/openldap/slapd.d/cn=config/olcDatabase={2}bdb.ldif"
    fi
    
    config_ldif="/etc/openldap/slapd.d/cn=config.ldif"
    if [ ! -f "$bdb_ldif" ]; then
        log "The system could not find the file $bdb_ldif. Exiting the LDAP server installation ..."
        return 1
    fi
    encrypt_pw=$(slappasswd -s "$ISF_LDAP_ROOT_PW")
    sed -i "s/\(^olcSuffix:\).*/\1 $ISF_LDAP_BASE_DOMAIN/" $bdb_ldif
    sed -i "s/\(^olcRootDN:\).*/\1 $ISF_LDAP_ROOT_DN/" $bdb_ldif
    grep -q "^olcRootPW:" $bdb_ldif
    if [ $? = 0 ]; then
        encrypt_pw=${encrypt_pw//\//\\/}
        sed -i "s/\(^olcRootPW:\).*/\1 $encrypt_pw/" $bdb_ldif
    else
        echo "olcRootPW: $encrypt_pw" >> $bdb_ldif
    fi
    # set ldap search max results
    ldap_search_size_limit=unlimited
    grep -q "^olcSizeLimit:" $bdb_ldif
    if [ $? = 0 ]; then
        sed -i "s/\(^olcSizeLimit:\).*/\1 $ldap_search_size_limit/" $bdb_ldif
    else
        echo "olcSizeLimit: $ldap_search_size_limit" >> $bdb_ldif
    fi
    
    #update  certs related section
    cat << _EOF >> $bdb_ldif
olcTLSCACertificateFile: /etc/openldap/cacerts/$cacert
olcTLSCertificateFile: /etc/openldap/certs/$scert.cert
olcTLSCertificateKeyFile: /etc/openldap/certs/$scert.key
olcTLSVerifyClient: never
_EOF

    ## Disable anonymous login
    #disable_anon="bind_anon"
    #grep -q "^olcDisallows:" $config_ldif
    #if [ $? = 0 ]; then
    #    sed -i "s/\(^olcDisallows:\).*/\1 $disable_anon/" $config_ldif
    #else
    #    echo "olcDisallows: $disable_anon" >> $config_ldif
    #fi

    mapping_user_encrypte_pw=$(slappasswd -s "$ISF_MAPPING_USERPW")
    # generate random password for pcmae_user
    PCMAEPW=$(cat /dev/urandom | head -1 | md5sum | head -c 8)
    
    BASEDC=`echo $ISF_LDAP_BASE_DOMAIN|awk -F ',' '{print $1}'|awk -F '=' '{print $2}'`
    BASE=$ISF_LDAP_BASE_DOMAIN
    ADMIN_SUB_DOMAIN="dc=$ISF_LDAP_ADMIN_SUB_DOMAIN"
    USERID=$ISF_MAPPING_USERNAME
    PASSWORD=$mapping_user_encrypte_pw
    
    generateInitLDIF

    slapadd -l $INIT_LDIF_FILE >> $INSTALL_LOG >/dev/null 2>&1
    if [ "$?" != "0" ]; then
        log "The system could not import the init file into the LDAP server."
        return 1
    fi
    chown -R ldap:ldap /var/lib/ldap >> $INSTALL_LOG 
    
    ISF_LDAP_BINDDN=`grep -e "^dn: uid=$ISF_MAPPING_USERNAME,.*$ISF_LDAP_BASE_DOMAIN" $INIT_LDIF_FILE | awk '{print $2}'`    
    ## Add LDAP server access control
    #echo "olcAccess: to dn.regex=\"dc=([^,]+),$ISF_LDAP_BASE_DOMAIN\" by dn.regex=\"uid=pcmae_user,dc=\$1,$ISF_LDAP_BASE_DOMAIN\" read by dn=\"$ISF_LDAP_BINDDN\" read by * auth" >> $bdb_ldif
    #echo "olcAccess: to * by * search by * auth" >> $bdb_ldif

    setup_ldaps
    
    service $service_name start >> $INSTALL_LOG
     if [ "$?" != "0" ]; then
        log "The system could not start the LDAP server (service $service_name startup). Exiting the LDAP installation ..."
        return 1
    fi
    
    # set LDAP server service to start with OS
    /sbin/chkconfig $service_name on
    log ""
    log "The installer successfully installed and configured the LDAP server."
    log ""
    log "Run \"slapcat -s $ISF_LDAP_BASE_DOMAIN\" to view the LDAP objects created for Platform Cluster Manager Advanced Edition."
    log ""
    log "Continue to run setupLDAPClient.sh on the Platform Cluster Manager Advanced Edition master host with the following information:"
    log "  LDAP base domain where users and groups will be retrieved: "$ISF_LDAP_BASE_DOMAIN
    log "  The LDAP sub domain directly under the base domain where users and groups can be assigned as Platform Cluster Manager Advanced Edition administrators: "$ISF_LDAP_ADMIN_SUB_DOMAIN
    log "  The distinguished name of the LDAP user mapped to Platform Cluster Manager Advanced Edition administrator: "$ISF_LDAP_BINDDN
    log ""
    log "You can use the following information to connect to the current LDAP server and manage it:"
    log "  LDAP root distinguished name (rootDN): "$ISF_LDAP_ROOT_DN
    log ""
}

#--------------------------------------------------------
# Name: uninstallLDAPServer if LDAP server install failed
#--------------------------------------------------------
uninstallLDAPServer()
{
    yum -y remove openldap-servers > /dev/null 2>&1
    rm -rf /etc/openldap/slapd.d
    rm -rf /var/lib/ldap
    rm -f $INIT_LDIF_FILE
}

prepare_iso(){
    check_ldap_server_required_pkgs
    if [ "$?" = "0" ]; then
        return 0
    fi

    until [ "${_isValid}" == "y" ]; do
        echo -e "\nSpecify the file path to the installation media for the operating system of the current host. \nThis can be the file path (or mount point) to the installation ISO file or to the device containing the installation disc, for example:\n\
   * For a mounted ISO image: /mnt/os \n\
   * For a file path to the ISO image file: /root/rhel-server-6.3-x86_64-dvd.iso \n\
   * For an installation disc in the CD-ROM drive: /dev/cdrom"
   echo -n "Specify the file path for the installation media: "
   
        read ISO_PATH
        #validate the value
        validate_iso_path ${ISO_PATH}
        if [ "$?" == "0" ]; then
            _isValid=y
        fi
    done
    #prepare local repo for yum
    if [ -f $ISO_PATH/media.repo ];then
        real_iso_path=$ISO_PATH
    else
        real_iso_path=$TMP_OS_ISO
    fi
    if [ ! -f /etc/yum.repos.d/ldap.local.repo ];then
        cat >> /etc/yum.repos.d/ldap.local.repo << EOF
[local-server]
name=rhel-local-server
baseurl=file://$real_iso_path/Server
enabled=1
gpgcheck=0
EOF
    fi
}

function validate_iso_path()
{
    local wrong_path='n'
    _kit_os=$1
    if [ x"$_kit_os" == "x" ]; then
        logerr "The file path is empty"
        return 1
    fi
    if [ -f "${_kit_os}" ]; then
        mkdir -p ${TMP_OS_ISO}
        _result=`file  ${_kit_os} | grep 'symbolic link'`
        if [ x"${_result}" == "x" ]; then 
            #One file
            _result=`file  ${_kit_os} | grep 'ISO'`
            if [ x"${_result}" == "x" ]; then 
                #Not ISO format
                wrong_path="y"
            else
                result=`mount -o loop ${_kit_os} ${TMP_OS_ISO} &> /dev/null`
                if [ "$?" != "0" ]; then
                    #Fail to mount this iso
                    logerr "The iso ${_kit_os} is invalid"
                    return 1
                fi
            fi
        else
            #One link
            _src_file=`readlink -f ${_kit_os}`
            _result=`file  ${_src_file} | grep 'ISO'`
            if [ x"${_result}" == "x" ]; then 
                #Not ISO format
                wrong_path="y"
            else
                result=`mount -o loop ${_kit_os} ${TMP_OS_ISO} &> /dev/null`
                if [ "$?" != "0" ]; then
                    #Fail to mount this iso
                    logerr "The iso ${_kit_os} is invalid"
                    return 1
                fi
            fi
        fi
        validate_iso_dir ${TMP_OS_ISO}
        if [ "$?" != "0" ] ; then
            wrong_path="y"
        fi

    else
       if [ ! -d "${_kit_os}" ]; then
           _result=`file  ${_kit_os} | grep 'symbolic link'`
           if [ x"${_result}" == "x" ]; then 
                #One device
                validate_iso_device ${_kit_os}
                if [ "$?" != "0" ] ; then
                   wrong_path="y"
                fi
           else
                #One link
                local _src_dev=`readlink -f ${_kit_os}`
                validate_iso_device ${_src_dev}
                if [ "$?" != "0" ] ; then
                   wrong_path="y"
                fi
           fi
       else
           validate_iso_dir "${_kit_os}"
           if [ "$?" != "0" ] ; then
               wrong_path="y"
           fi
       fi
    fi
    
    if [ "$wrong_path" = "y" ]; then
        logerr "${_kit_os} is invalid. Specify the correct ISO file path, the mount point or the device(for example, /dev/cdrom)."
        return 1
    else
        #log "${_kit_os} is valid"
        return 0
    fi
}

function validate_iso_dir()
{
    local _iso_dir=$1
    if [ ! -f  ${_iso_dir}/media.repo ]; then
         logerr "There is no media.repo in ${_iso_dir}."
         return 1
    fi
    local _os_version=`cat ${_iso_dir}/media.repo|grep "name="|awk -F "name=" '{print $2}'|awk  '{print $NF}'`
    #One invalid diectory
    if [ x"${_os_version}" == "x" ]; then
         logerr "There is no OS in ${_iso_dir}."
         return 1
    fi
    _result=`cat /etc/system-release|grep ${_os_version}`
    if [ x"${_result}" == "x" ]; then
         logerr "The OS version ${_os_version} of ${_iso_dir} is invalid."
         return 1
    fi
    return 0
}

function validate_iso_device()
{
    local _device=$1
    mkdir -p ${TMP_OS_ISO}
    _result=`mount -o loop ${_device} ${TMP_OS_ISO} &> /dev/null`
    if [ "$?" != "0" ]; then
         #Fail to mount this iso
         logerr "The device ${_device} is invalid"
         return 1
    fi
    
    validate_iso_dir ${TMP_OS_ISO}
    if [ "$?" != "0" ] ; then
        return 1
    fi
    return 0
}

function clear_mounted_iso()
{
    if [ -d $TMP_OS_ISO ];then
        umount -f $TMP_OS_ISO &> /dev/null
        rm -rf $TMP_DIR
    fi
    rm -rf /etc/yum.repos.d/ldap.local.repo
}

exiton_prepare()
{
    stty echo
    trap '' $TRAP_SIGNAL
    log ""
    log "Installation interrupted. Uninstalling..."
    clear_mounted_iso
    exit $TRAP_EXIT_CODE
}

exiton_LDAP()
{
    trap '' $TRAP_SIGNAL
    log ""
    log "Installation interrupted. Uninstalling..."
    uninstallLDAPServer
    clear_mounted_iso
    exit $TRAP_EXIT_CODE
}

setup_ldaps()
{
    gencerts
    update_sysldapconf
}

update_sysldapconf()
{
    if [ ! -f /etc/sysconfig/ldap.orig ]; then
        \cp -fr /etc/sysconfig/ldap /etc/sysconfig/ldap.orig
    fi
    #create back up file
    cat <<_EOF > /etc/sysconfig/ldap
SLAPD_LDAP=yes
SLAPD_LDAPI=yes
SLAPD_LDAPS=yes
_EOF
}

#update openssl.cnf
update_opensslconf()
{
    cp -rf $sslconf $baksslconf

    sed -i 's/\(countryName[[:space:]]*=[[:space:]]\)match/\1optional/g' $sslconf
    sed -i 's/\(stateOrProvinceName[[:space:]]*=[[:space:]]\)match/\1optional/g' $sslconf
    sed -i 's/\(organizationName[[:space:]]*=[[:space:]]\)match/\1optional/g' $sslconf

}

#generate CA certs
gencacert()
{
    if [ -d "$catop" ]; then
        mv $catop $bakcatop
    fi

    #prepare dir structure
    mkdir -p $catop/{certs,crl,newcerts,private}
    touch $catop/index.txt
    echo "00" > $catop/serial

    #gen ca private key
    openssl genrsa -out $cakey  2048 > /dev/null 2>&1
    
    #gen ca req
    openssl req -new -key $cakey -out $careq -subj $cnstr

    #sign ca req
    openssl ca -passin pass:$keypass -create_serial -out $cacert -batch -keyfile $cakey -selfsign -extensions v3_ca -infiles $careq
    
}

#gen normal cert
gencert()
{
    [ "x$1" = "x" ] && exit -1 

    name=$1
    #gen openssl pivate key
    openssl genrsa -out $name.key 2048 > /dev/null 2>&1

    #gen openssl sign request
    openssl req -new -key $name.key -out $name.csr -subj /CN=$name

    #sign server cert request
    openssl ca -create_serial -in $name.csr -out $name.cert -cert $cacert -keyfile $cakey  -passin pass:$keypass -batch -days 3650
}

#generate cacert and server/client side certs and keys
gencerts()
{
    update_opensslconf
    gencacert

    gencert $scert
    gencert $ccert

    if [ -d $bakcatop ]; then 
        rm -fr $catop
        mv $bakcatop $catop
    fi

    if [ -d $baksslconf ]; then
        rm -fr $sslconf
        mv $baksslconf $sslconf
    fi
    
    # update /etc/openldap/ldap.conf
    cp /etc/openldap/ldap.conf /etc/openldap/ldap.conf.orig
    cat << _EOF > /etc/openldap/ldap.conf
    TLS_CERTDIR     /etc/openldap/certs
    TLS_REQCERT allow
_EOF

    #put the certs to correct place
    mkdir /etc/openldap/{certs,cacerts}

    cp $scert.cert $scert.key /etc/openldap/certs
    cp $cacert /etc/openldap/cacerts

    chown ldap:ldap /etc/openldap/{certs,cacerts} -R
}

rollback_ldaps()
{
    #role back up file
    \cp -fr /etc/sysconfig/ldap.orig /etc/sysconfig/ldap 
    if [ -d $bakcatop ]; then 
        rm -fr $catop
        mv $bakcatop $catop
    fi
}


TRAP_SIGNAL="1 2 3 15"
TRAP_EXIT_CODE=99
trap exiton_prepare $TRAP_SIGNAL
prepareInstallLDAP
if [ "$?" != "0" ]; then
    clear_mounted_iso
    exit 1
fi


trap exiton_LDAP $TRAP_SIGNAL
installAndConfigLDAPServer
if [ "$?" != "0" ]; then
    uninstallLDAPServer
    exit 1
fi
clear_mounted_iso
#rm -f $INIT_LDIF_FILE

exit 0
