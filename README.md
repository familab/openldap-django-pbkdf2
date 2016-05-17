Django's version of PBKDF2 for OpenLDAP
=======================

pw-django-pbkdf2.c provides PBKDF2 key derivation functions in OpenLDAP.

Schemes:

 * {PBKDF2-SHA256}

# Differences between this and pw-pbkdf2.c

Django base 64 encodes the salt before using it to generate the hash. It also
uses base64 instead of adapted base64.

Additionaly the salt is required to be alphanumeric (this is not implimented in 
  my library)

# Requirements
  * Nettle 2.7.1 or later

# Installations

First, You need to configure and build OpenLDAP with --enable-modules option.

~~~
$ cd <OPENLDAP_BUILD_DIR>/contrib/slapd-modules/passwd/
$ git clone https://github.com/familab/openldap-django-pbkdf2
$ cd openldap-django-pbkdf2/
$ make
# make install
~~~

# Configration

In slapd.conf:

~~~
moduleload pw-django-pbkdf2.so
~~~

You can also tell OpenLDAP to use the schemes when processing LDAP
Password Modify Extended Operations, thanks to the password-hash
option in slapd.conf. For example:

~~~
password-hash {PBKDF2-SHA256}
~~~

# Testing

You can get hash to use slappasswd.

~~~
$ slappasswd -o module-load=pw-django-pbkdf2.la -h {PBKDF2} -s secret
{PBKDF2-SHA256}24000$WR2ImpVHny1rAwqo$vs0lP1a28dlTQHgL1ehH616Njd6ApHYxzHqzBDBYkc4=
~~~

A quick way to test whether it's working is to customize the rootdn and
rootpw in slapd.conf, eg:

~~~
rootdn "cn=Manager,dc=example,dc=com"
rootpw {PBKDF2-SHA256}24000$WR2ImpVHny1rAwqo$vs0lP1a28dlTQHgL1ehH616Njd6ApHYxzHqzBDBYkc4=
~~~

Then to test, run something like:

~~~
$ ldapsearch -x -b "dc=example,dc=com" -D "cn=Manager,dc=example,dc=com" -w secret
~~~

# Debugging
You can specify -DSLAPD_PBKDF2_DEBUG flag for debugging.

# Message Format

~~~
{PBKDF2-SHA256}<Iteration>$<Base64 Salt>$<Base64 DK>
~~~

# Sample code for Python Passlib

~~~
#!/usr/bin/env python

from passlib.hash import django_pbkdf2_sha256
print(django_pbkdf2_sha256.encrypt("secret", rounds=24000))
~~~

# References

* [RFC 2898 Password-Based Cryptography][^1]
[^1]: http://tools.ietf.org/html/rfc2898

* [PKCS #5 PBKDF2 Test Vectors][^2]
[^2]: http://tools.ietf.org/html/draft-josefsson-pbkdf2-test-vectors-06

* [RFC 2307 Using LDAP as a Network Information Service][^3]
[^3]: http://tools.ietf.org/html/rfc2307

* [Python Passlib][^4]
[^4]: http://pythonhosted.org/passlib/

* [Adapted Base64 Encoding][^5]
[^5]: http://pythonhosted.org/passlib/lib/passlib.utils.html#passlib.utils.ab64_encode

# License
This work is part of OpenLDAP Software <http://www.openldap.org/>.

Copyright 2009-2013 The OpenLDAP Foundation.
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted only as authorized by the OpenLDAP
Public License.

A copy of this license is available in the file LICENSE in the
top-level directory of the distribution or, alternatively, at
<http://www.OpenLDAP.org/license.html>.

# ACKNOWLEDGEMENT
This work was initially developed by HAMANO Tsukasa <hamano@osstech.co.jp>

Contributor:
- Luca Bruno(lucab)
- Lance Hudson(lancehudson)
