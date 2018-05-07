#!/bin/bash

# This script help to set up an LDAP server in CentOS 7.x or RHEL 7.x 
# By Leo.C.Wu

function installpkgs()
{
    echo "Removing installed ldap packages..."
    echo "Installing ldap packages..."
    pkgs="openldap-clients openldap-servers migrationtools"
    yum -y remove $pkgs > /dev/null 2>&1

    rm -fr /etc/openldap/ /var/lib/ldap/

    yum -y install $pkgs

    if [ "x$?" != "x0" ]; then
        echo "Cannot install ldap packages, please check your yum repositories"
        exit 1
    fi
}

function configldap()
{
    echo "Configuring ldap service..."
    
    #update slapd configuration files
    monitorldif="/etc/openldap/slapd.d/cn=config/olcDatabase={1}monitor.ldif"
    sed -i "s/my-domain/$basedn/g"  $monitorldif

    hdbldif="/etc/openldap/slapd.d/cn=config/olcDatabase={2}hdb.ldif"
    if [ "x$rootdn" != "x" ]; then
        sed -i "s/Manager/$rootdn/g"  $monitorldif
    fi

    sed -i -e '/olcSuffix:.*/d; /olcRootDN.*/d'  $hdbldif
    cat >> $hdbldif << _EOF
olcSuffix: dc=$basedn,dc=com
olcRootDN: cn=$rootdn,dc=$basedn,dc=com
olcRootPW: $rootpw 
_EOF

    #create ldap databases
    cp  /usr/share/openldap-servers/DB_CONFIG.example /var/lib/ldap/DB_CONFIG
    chown -R ldap:ldap /var/lib/ldap
    
    #do configuration test
    slaptest -u

    if [ "x$?" != "x0" ]; then
        echo "Configuration test failed, check your configuration and run this script again"
        exit 1
    fi

    systemctl start slapd

    #create ldap schema
    schempath=/etc/openldap/schema
    for ldif in `ls $schempath/*.ldif`; 
    do
        ldapadd -Y EXTERNAL -H ldapi:/// -D "cn=config" -f "$ldif"
    done

    #import base.ldif
    export LDAP_DEFAULT_MAIL_DOMAIN="${basedn}.com"
    export LDAP_BASEDN="dc=${basedn},dc=com"

    /usr/share/migrationtools/migrate_base.pl > /tmp/base.ldif
    
    ldapadd -x -w $rootpw -D "cn=$rootdn,dc=$basedn,dc=com" -f /tmp/base.ldif

    # migrate_users.pl to create users
    # migrate_groups.pl to create groups
    # ldapadd -x to add them to ldap servers.
}


function startldap()
{
    echo "Starting ldap service..."
    systemctl enable slapd
    systemctl stop slapd
    systemctl start slapd
    systemctl status slapd
}

function checkargs()
{
    if [ "x$BASEDN" != "x" ]; then
        basedn=$BASEDN
    fi

    if [ "x$ROOTDN" != "x" ]; then
        rootdn=$ROOTDN
    fi

    if [ "x$ROOTPW" != "x" ]; then
        rootpw=$ROOTPW
    fi
}

##################
####   main   #### 
##################

basedn='xworks'
rootdn='Manager'
rootpw='letmein'

checkargs

installpkgs

configldap

startldap
