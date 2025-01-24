# WACE Apache Module

The general objective of this project is to build machine
learning-assisted web application firewall mechanisms for the
identification, analysis and prevention of computer attacks on web
applications. The main idea is to combine the flexibility provided by
the classification procedures obtained from machine learning models
with the codified knowledge integrated in the specification of the
[OWASP Core Rule Set](https://coreruleset.org/) used by the [ModSecurity WAF](https://www.modsecurity.org/) to detect attacks, while
reducing false positives. The next figure shows a high-level
overview of the architecture:

![WACE architecture overview](https://github.com/tilsor/ModSecIntl_wace_core/blob/main/docs/images/architecture.jpg?raw=true "WACE architecture overview")

This repository contains the Apache module that connects ModSecurity
to the WACE backend. 

Please see the [WACE core
repo](https://github.com/tilsor/ModSecIntl_wace_core) and the [machine
learning model
repo](https://github.com/tilsor/ModSecIntl_roberta_model) for the rest
of the components.

You can find more information about the project, including published
research articles, at the [WAF Mind
site](https://www.fing.edu.uy/inco/proyectos/wafmind)

## Installation
RPM packages for Red Hat Enterprise Linux 8 (or any compatible
distribution) are provided in the [releases
page](https://github.com/tilsor/ModSecIntl_wace_core/releases).

For compilation and manual installation instructions, please see the
[docs](https://github.com/tilsor/ModSecIntl_wace_core/tree/main/docs) directory.

### Rocky Linux 8

git clone repo ~/waceserver
git clone repo ~/mod_wace
cp ~/waceserver/wace.proto ~/mod_wace/wace.proto
cd ~/mod_wace
mkdir -p cmake/build
cd cmake/build 
cmake3 ../..
make
cp libgrpc_wace_client.so /usr/lib/
ldconfig 
apxs -Wl -Wc -cia -I/usr/include/libxml2 -I~/mod_wace -L~/mod_wace/cmake/build/ -lgrpc_wace_client ~/mod_wace/mod_wace.c 
cp ~/mod_wace/crs_rules/* /etc/httpd/modsecurity.d/owasp-crs/rules/
sed -i -e '$a\SecRuleRemoveById 949110' /etc/httpd/modsecurity.d/owasp-crs/rules/RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf
sed -i -e '$a\WaceServerUrl localhost:50051' /etc/httpd/conf/httpd.conf
execstack -c /usr/lib64/httpd/modules/mod_wace.so
systemctl restart httpd

## Licence
Copyright (c) 2022 Tilsor SA, Universidad de la República and
Universidad Católica del Uruguay. All rights reserved.

WACE and its components are distributed under Apache Software License
(ASL) version 2. Please see the enclosed LICENSE file for full
details.
