#!/bin/bash

catop=/etc/pki/CA
bakcatop=/etc/pki/CA.orig

keypass="Lemtein"
cnstr="/CN=IBM"

#for ca keys
cakey=ca.key
careq=ca.req
cacert=ca.cert

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

gencert()
{
    [ "x$1" = "x" ] && exit -1 

    #serialfile=$catop/serial
    
    #printf "%d$((`cat $serialfile` + 1))\n" > $serialfile

    #echo "" > $catop/index

    name=$1
    #gen openssl pivate key
    openssl genrsa -out $name.key 2048 > /dev/null 2>&1

    #gen openssl sign request
    openssl req -new -key $name.key -out $name.csr -subj /CN=$name

    #sign server cert request
    openssl ca -create_serial -in $name.csr -out $name.cert -cert $cacert -keyfile $cakey  -passin pass:$keypass -batch
}

#main gen cacert and server/client certs
gencacert
gencert server
gencert client
if [ -d $bakcatop ]; then 
    rm -fr $catop
    mv $bakcatop $catop
fi
