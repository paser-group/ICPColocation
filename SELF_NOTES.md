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

#### Example-7

Location: `/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/puppet-ec2api-2018-06/sync.pp`

Hard-coded user name (`$system_user = 'ec2api'`) propagated from paramters into the `exec`
`user => $system_user`. 


#### Example-8 

Location: `/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/puppet-ec2api-2018-06/postgresql.pp`

Hard-coded user name (`$user = 'ec2api'`) propagated from parameters into the 
`::openstacklib::db::postgresql {` body of `password_hash => postgresql_password($user, $password)`. 

#### Example-9

Location: `/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/puppet-ec2api-2018-06/mysql.pp`

Hard-coded user name (`$user = 'ec2api'`) propagated from parameters into the 
`::openstacklib::db::mysql {` body of `user => $user,`. 

#### Example-10 

Location: `/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/puppet-ec2api-2018-06/`

Insecure HTTP used in `keystone/auth.pp` (`$public_url = 'http://127.0.0.1:8788'`). Propagates to
`keystone::resource::service_identity` (`public_url => $public_url`). 


#### Example-11

Location: `/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/fuel-plugin-plumgrid-2018-06/deployment_scripts/puppet/manifests/plumgrid_nova_compute.pp` 

Example false positives that can be mitigated using a parser: 
> $admin_password = try_get_value($neutron_config, 'keystone/admin_password')
> $admin_identity_protocol = get_ssl_property($ssl_hash, {}, 'keystone', 'admin', 'protocol', 'http')

Another example:
> $nova_hash = hiera_hash('nova', {})
> $nova_sql_password = pick($nova_hash['db_password'])
> line => "connection = mysql://nova:$nova_sql_password@$mgmt_vip/nova?read_timeout=60", in `file {}` 

Another example: 
> $neutron_config  = hiera_hash('quantum_settings', {})
> $metadata_secret = pick($neutron_config['metadata']['metadata_proxy_shared_secret'], 'root')
> $neutron_db_password = $neutron_config['database']['passwd']
> $neutron_db_user = pick($neutron_config['database']['user'], 'neutron')

Another example: 
> $access_hash = hiera_hash('access', {})
> $admin_username = pick($access_hash['user'])
> $admin_password = pick($access_hash['password'])

Another example:
> password_hash => mysql_password($password),
> password_hash => postgresql_password($user, $password),

Another example:
> $configure_user = true,




#### Example-12 

Location:`/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/fuel-plugin-plumgrid-2018-06/deployment_scripts/puppet/modules/plumgrid/manifests/init.pp`

`class plumgrid` is a class that `inherits plumgrid::params` means a class needs sth. that comes from 
`params.pp` which is `plumgrid/manifests/` 

Also, `$rest_ip = '0.0.0.0',` is not used anywhere in the module (`plumgrid/`) 

#### Example-13 

Location:`/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/fuel-plugin-plumgrid-2018-06/deployment_scripts/puppet/modules/plumgrid/manifests`

> $lxc_data_path = '/var/lib/libvirt/filesystems/plumgrid-data'
> target => "${lxc_data_path}/root/.ssh/authorized_keys" 

This is not detected by SLIC ... needs better parsing 

#### Example-14 

Location:`/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/puppet-heat-2018-06/manifests/keystone/auth_cfn.pp`

Example of insecure HTTP being assigned 

> keystone::resource::service_identity{ 
> $public_url           = 'http://127.0.0.1:8000/v1',
> $admin_url            = 'http://127.0.0.1:8000/v1',
> $internal_url         = 'http://127.0.0.1:8000/v1',
> public_url          => $public_url,
> admin_url           => $admin_url,
> internal_url        => $internal_url,

#### Example-15

Location:`/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/puppet-heat-2018-06/example/site.pp`

Nice examples on how the modules inside `/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/puppet-heat-2018-06/manifests/` are used: 

1. Let us consider the following: 
>  class { '::heat::db::mysql':
>    password => 'heat',
>  }

`heat` will be propagated into `class heat::db::mysql` as `$password`.
Then used in `password_hash => mysql_password($password),` within `::openstacklib::db::mysql {`
inside `class heat::db::mysql` 

So if we have a script that looks like above then we can get a full flow of information of 
data `heat`


2. Let us consider sth. else: 
>  class { '::heat::keystone::authtoken':
>    password => 'password',
>  }

`password` will be propagated into `heat::keystone::authtoken(){}` as `$password`.
Then used in `password => $password,` within `keystone::resource::authtoken {}`
inside `class heat::keystone::authtoken(){}` 

So if we have a script that looks like above then we can get a full flow of information of 
data `password` 

3. Finally, let us consider this:
>  class { '::heat::engine':
>    auth_encryption_key => 'whatever-key-you-like',
>  }

`whatever-key-you-like` will be propagated into `class heat::engine(){}` as `$auth_encryption_key,`.
Then used in `$param_size = size($auth_encryption_key)` and `'DEFAULT/auth_encryption_key': value => $auth_encryption_key, secret => true;` resptecively, within `class heat::engine (){}` and `heat_config {}`
inside `class heat::engine (){}` 

So if we have a script that looks like above then we can get a full flow of information of 
data `whatever-key-you-like` 


#### Example-16

Location:`/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/fuel-plugin-ceilometer-redis-2018-06/deployment_scripts/puppet/modules/redis/tests/init.pp`

`conf_bind => '0.0.0.0'`, used in `init.pp` is used no where ... this is a false positive 

#### Example-17 

Location: ``

> $mysql_opts = hiera('mysql')
> $mysql_password = $mysql_opts['root_password']
> $sql_connect = "mysql -h ${galera_host} -uroot -p${mysql_password}"
... 
> $sql_query = "${sql_connect} -e \"${db_query}; ${table_query}; ${update_query};\""

Even though there is a SQL-injection like statement, the value is not hard-coded rather coming
from hiera(). This should not be flagged. 


#### Example-18

Location: `/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/fuel-plugin-scaleio-2018-06/deployment_scripts/puppet/manifests/nova.pp`

```
if $scaleio['existing_cluster'] {
    $client_password = $password
  } else {
    $client_password_str = base64('encode', pw_hash($password, 'SHA-512', 'scaleio.client.access'))
    $client_password = inline_template('Sio-<%= @client_password_str[33..40] %>-<%= @client_password_str[41..48] %>')
}
```

`client_password` later used in `class {'::scaleio_openstack::nova':}` as `gateway_password`

#### Example-19

Location: `/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/fuel-plugin-scaleio-2018-06/deployment_scripts/puppet/manifests/cluster.pp`

> $client_password_str = base64('encode', pw_hash($password, 'SHA-512', 'scaleio.client.access'))
> $client_password = inline_template('Sio-<%= @client_password_str[33..40] %>-<%= @client_password_str[41..48] %>')

after >50 lines later used as 

```
        scaleio::cluster {'Create scaleio client user':
          ensure          => 'present',
          client_password => $client_password,
          require         => [Protection_domain_ensure[$protection_domain_array], Sds_ensure[$to_add_sds_names]],
        }
```

in `scaleio::login {'Normal':}`


#### Example-20

Location: `/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/puppet-aodh-2018-06/examples/aodh.pp`

One example: 
```
class { '::aodh::keystone::authtoken':
  password => 'a_big_secret',
}
```
^ this will call `$password` in `class aodh::keystone::authtoken(){}` ... that is later used 
as `password => $password,` in `keystone::resource::authtoken { 'aodh_config':}`

Another example: 
```
class { '::aodh::auth':
  auth_password => 'a_big_secret',
}
```

`$auth_password` called in `class aodh::auth (){}` and later used as
`'service_credentials/password' : value => $auth_password, secret => true;` in `aodh_config {}` 