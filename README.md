ROT-13 Password Factory [![Maven Central](https://maven-badges.herokuapp.com/maven-central/com.github.marschall/rot13-password-provider/badge.svg)](https://maven-badges.herokuapp.com/maven-central/com.github.marschall/rot13-password-provider) [![Build Status](https://travis-ci.org/marschall/rot13-password-provider.svg?branch=master)](https://travis-ci.org/marschall/rot13-password-provider)
=======================

An Elytron [PasswordFactory](https://docs.wildfly.org/20/WildFly_Elytron_Security.html#Passwords) that supports [ROT-13](https://en.wikipedia.org/wiki/ROT13) encrypted passwords.


```xml
<dependency>
  <groupId>com.github.marschall</groupId>
  <artifactId>rot13-password-factory</artifactId>
  <version>1.0.0</version>
</dependency>
```

Installation
------------
cd modules/system/layers/base/
mkdir -p com/github/marschall/rot13/main
            </http-authentication-factory>
```

Usage
-----


```xml
        <subsystem xmlns="urn:wildfly:elytron:14.0" final-providers="combined-providers" disallowed-providers="OracleUcrypto">
            <providers>
                <aggregate-providers name="combined-providers">
                    <!-- ... -->
                    <providers name="rot13"/>
                </aggregate-providers>
                <!-- ... -->
                <provider-loader name="rot13" module="com.github.marschall.rot13"/>
            </providers>

                <security-domain name="Rot13ManagementDomain" default-realm="JdbcRot13Realm" permission-mapper="default-permission-mapper">
                    <realm name="JdbcRot13Realm" role-decoder="groups-to-roles"/>
                </security-domain>

                <jdbc-realm name="JdbcRot13Realm">
                  <principal-query data-source="ExampleDS" sql="SELECT 'Y25mZmpiZXE=' FROM dual WHERE ? is not null">
                    <simple-digest-mapper hash-encoding="base64" algorithm="rot-13" password-index="1"/>
                  </principal-query>
                  <principal-query data-source="ExampleDS" sql="SELECT 'SuperUser' FROM dual WHERE ? is not null">
                    <attribute-mapping>
                      <attribute index="1" to="groups"/>
                    </attribute-mapping>
                  </principal-query>
                </jdbc-realm>

                <http-authentication-factory name="management-http-authentication" security-domain="Rot13ManagementDomain" http-server-mechanism-factory="global">
                    <mechanism-configuration>
                        <mechanism mechanism-name="BASIC">
                            <mechanism-realm realm-name="JdbcRot13Realm"/>
                        </mechanism>
                    </mechanism-configuration>
```


Caveats
-------

How sure whether `Rot13Password` should be `OneWayPassword` or `TwoWayPassword`. `TwoWayPassword` is technically correct but `OneWayPassword` is what custom hashes most likely would be.

https://rot13.com/
https://www.base64encode.org/

password -> cnffjbeq -> Y25mZmpiZXE=
