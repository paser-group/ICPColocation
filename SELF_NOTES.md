# Possible Trajectories 

## Sep 28, 2020 

1. First get the ICP 
2. Identify attribute or variable from the ICP
3. Track the variable or attribute upwards and downwards 
4. Search within the module 

### Examples:

#### Example-1

`$http_host = '0.0.0.0'` ... no parsing error but `$http_host` is used as a default in `class cdh::hue(` that `inherits cdh::hue::defaults` 
Source: `/Users/arahman/PRIOR_NCSU/SECU_REPOS/wiki-pupp/cdh4-2018-06/manifests/` ... `class cdh::hue` is in hue.pp and `cdh::hue::defaults` is in `hue/defaults.pp` 
In `class cdh::hue(`,  `user { 'hue'` is a true positive. 

#### Example-2 

In `cdh::oozie`, `$url` is has a valid insecure HTTP, but is not used to setup a server, rather used in 
`content => "# NOTE:  This file is managed by Puppet. export OOZIE_URL='${url}'",` ... note the usage of ${url} ...
access to a variable. 
In `cdh::oozie` ... oozie.pp resides in `/Users/arahman/PRIOR_NCSU/SECU_REPOS/wiki-pupp/cdh4-2018-06/manifests/`

#### Example-3

A hard-coded password `$jdbc_password = 'oozie'` is specified in `cdh::oozie::defaults`, located in `oozie/defaults`, which is used in 
`cdh::oozie::server` as `$jdbc_password = $cdh::oozie::defaults::jdbc_password`, which is not used anywhere later. 


#### Example-4

In `cdh::hive::metastore::mysql` using `command`, an actual user password us used. See below: 

```
command => "/usr/bin/mysql ${username_option} ${password_option} -e \"
CREATE USER '${db_user}'@'localhost' IDENTIFIED BY '${db_pass}';
CREATE USER '${db_user}'@'127.0.0.1' IDENTIFIED BY '${db_pass}';
GRANT ALL PRIVILEGES ON ${db_name}.* TO '${db_user}'@'localhost' WITH GRANT OPTION;
GRANT ALL PRIVILEGES ON ${db_name}.* TO '${db_user}'@'127.0.0.1' WITH GRANT OPTION;
FLUSH PRIVILEGES;\"",

```

`$db_pass = $cdh::hive::jdbc_password`, meaning $db_pass comes from `cdh::hive::`, which in turn comes from `$jdbc_password = $cdh::hive::defaults::jdbc_password,` 
in `cdh::hive::defaults`. there is hard-coded password for `$jdbc_password` i.e. `$jdbc_password = 'hive'`. 


#### Example-5 

  
Variables or attributes that have HTTP URL first needs to be checked for HTTPS. If exists then report, 
otherwise do not. 
`location  => "http://repos.mesosphere.io/` and `source  => "http://repos.mesosphere.io/el/${osrel}/noarch/RPMS/`
are examples in `/Users/arahman/PRIOR_NCSU/SECU_REPOS/wiki-pupp/mesos-2018-06/manifests/repo.pp` (`class mesos::repo`).

 
#### Example-6 

In `class nginx::ssl` located in `/Users/arahman/PRIOR_NCSU/SECU_REPOS/wiki-pupp/nginx-2018-06`
uses a template file using `template()` for `file{}` `content => template('nginx/ssl.conf.erb')`.
The ERB file has a hard-coded SSL cipher that is an example of a hard-coded secret. 
So we need to check for SSL cipher or SSH keys in ERB files as well. 

 

