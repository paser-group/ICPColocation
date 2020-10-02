# Track the Data Flow 

### Wikimedia Exploration, Sep 28 2020 

1. First get the ICP 
2. Identify attribute or variable from the ICP
3. Track the variable or attribute upwards and downwards 
4. Search within the module 

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


### Openstack Exploration, Sep 30 2020 

#### Example-1

Location: `/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/puppet-ec2api-2018-06/sync.pp`

Hard-coded user name (`$system_user = 'ec2api'`) propagated from paramters into the `exec`
`user => $system_user`. 


#### Example-2 

Location: `/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/puppet-ec2api-2018-06/postgresql.pp`

Hard-coded user name (`$user = 'ec2api'`) propagated from parameters into the 
`::openstacklib::db::postgresql {` body of `password_hash => postgresql_password($user, $password)`. 

#### Example-3

Location: `/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/puppet-ec2api-2018-06/mysql.pp`

Hard-coded user name (`$user = 'ec2api'`) propagated from parameters into the 
`::openstacklib::db::mysql {` body of `user => $user,`. 

#### Example-4 

Location: `/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/puppet-ec2api-2018-06/`

Insecure HTTP used in `keystone/auth.pp` (`$public_url = 'http://127.0.0.1:8788'`). Propagates to
`keystone::resource::service_identity` (`public_url => $public_url`). 


#### Example-5

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




#### Example-6

Location:`/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/fuel-plugin-plumgrid-2018-06/deployment_scripts/puppet/modules/plumgrid/manifests/init.pp`

`class plumgrid` is a class that `inherits plumgrid::params` means a class needs sth. that comes from 
`params.pp` which is `plumgrid/manifests/` 

Also, `$rest_ip = '0.0.0.0',` is not used anywhere in the module (`plumgrid/`) 

#### Example-7

Location:`/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/fuel-plugin-plumgrid-2018-06/deployment_scripts/puppet/modules/plumgrid/manifests`

> $lxc_data_path = '/var/lib/libvirt/filesystems/plumgrid-data'
> target => "${lxc_data_path}/root/.ssh/authorized_keys" 

This is not detected by SLIC ... needs better parsing 

#### Example-8

Location:`/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/puppet-heat-2018-06/manifests/keystone/auth_cfn.pp`

Example of insecure HTTP being assigned 

> keystone::resource::service_identity{ 
> $public_url           = 'http://127.0.0.1:8000/v1',
> $admin_url            = 'http://127.0.0.1:8000/v1',
> $internal_url         = 'http://127.0.0.1:8000/v1',
> public_url          => $public_url,
> admin_url           => $admin_url,
> internal_url        => $internal_url,

#### Example-9

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

#### Example-10 

Location: `/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/puppet-neutron-2018-06` 

1. In `manifests/agents/ml2/networking_baremetal.pp` ,   `$auth_url` ('http://127.0.0.1:35357') is propagated into `ironic_neutron_agent_config {}` as `'ironic/auth_url': value => $auth_url;`

2. In `manifests/agents/ml2/networking_baremetal.pp` , `$password` propagated into `ironic_neutron_agent_config {}` as `'ironic/password': value => $password;`

3. In `manifests/agents/ovn_metadata.pp`, `$auth_ca_cert`, `$shared_secret`, `$nova_client_cert`  are propagated into 

>  'DEFAULT/auth_ca_cert':                   value => $auth_ca_cert;
>  'DEFAULT/metadata_proxy_shared_secret':   value => $shared_secret;
> 'DEFAULT/nova_client_cert':               value => $nova_client_cert;

Need to check how these (`$auth_ca_cert`, `$shared_secret`, `$nova_client_cert`) values are assigned. 
Similar things happen in `manifests/agents/ml2/metadata.pp`  

4. `content => template('neutron/n1kv.conf.erb'),` in `n1kv_vem.pp`. Need to check content of the ERB file 

5. In `manifests/agents/l2gw.pp` , `$l2_gw_agent_priv_key_base_path, $l2_gw_agent_cert_base_path, $l2_gw_agent_ca_cert_base_path`

> 'ovsdb/l2_gw_agent_priv_key_base_path':     value => $l2_gw_agent_priv_key_base_path;
> 'ovsdb/l2_gw_agent_cert_base_path':         value => $l2_gw_agent_cert_base_path;
> 'ovsdb/l2_gw_agent_ca_cert_base_path':      value => $l2_gw_agent_ca_cert_base_path;

Need to check where `$l2_gw_agent_priv_key_base_path, $l2_gw_agent_cert_base_path, $l2_gw_agent_ca_cert_base_path` is coming from. 

6. In `manifests/agents/dhcp.pp`, `$ovsdb_agent_ssl_key_file , $ovsdb_agent_ssl_cert_file, $ovsdb_agent_ssl_ca_file` used in `neutron_dhcp_agent_config {}` and `$req_ssl_opts = {}` 

Need to check where `$ovsdb_agent_ssl_key_file , $ovsdb_agent_ssl_cert_file, $ovsdb_agent_ssl_ca_file` is coming from. 

7. In `manifests/db/postgresql.pp` , `$password,` propagates into `password_hash => postgresql_password($user, $password),` ... this function gives hash , not plain password. `$user ` propagates into `::openstacklib::db::postgresql {` as `user => $user,`

8. In `manifests/db/mysql.pp` , `$password,` propagates into `password_hash => mysql_password($password),` ... this function gives hash , not plain password. `$user ` propagates into `::openstacklib::db::postgresql {` as `user => $user,`

9. In `manifests/keystone/auth.pp` we see 

>  $password,
>  $public_url          = 'http://127.0.0.1:9696',
>  $admin_url           = 'http://127.0.0.1:9696',
>  $internal_url        = 'http://127.0.0.1:9696',

later being used in `keystone::resource::service_identity {}` as 

> password            => $password,
> public_url          => $public_url,
> admin_url           => $admin_url,
> internal_url        => $internal_url,

No function call ... all plain text 

10. In `manifests/keystone/authtoken.pp` we see 

>  $username                       = 'neutron',
>  $password                       = $::os_service_default,
>  $auth_url                       = 'http://localhost:5000',
>  $www_authenticate_uri           = 'http://localhost:5000',

later being used in `keystone::resource::authtoken {}` as 

>    username                       => $username,
>    password                       => $password,
>    auth_url                       => $auth_url,
>    www_authenticate_uri           => $www_authenticate_uri_real,

11. In `manifests/plugins/ovs/opendaylight.pp`, `$odl_username, $odl_password, $odl_check_url` was used in 

>  command   => "${curl_post} -u ${odl_username}:${odl_password} -d '${rest_data}' ${cert_rest_url}",
>  unless    => "${curl_get} -u ${odl_username}:${odl_password} -d '${rest_get_data}' ${cert_rest_get} | grep -q ${cert_data}",
>  command   => "curl -k -o /dev/null --fail --silent --head -u ${odl_username}:${odl_password} ${odl_check_url_parsed}",

Need to see how the values of `$odl_username, $odl_password, $odl_check_url` are flowing 

12. In `manifests/plugins/plumgrid.pp`,  `$connection, $admin_password, $auth_protocol, $l2gateway_sw_username, $l2gateway_sw_password`  
 is  used in 

> 'PLUMgridDirector/username':             value => $username;
> 'PLUMgridDirector/password':             value => $password, secret =>true;
> 'l2gateway/sw_username':                 value => $l2gateway_sw_username;
> 'l2gateway/sw_password':                 value => $l2gateway_sw_password, secret =>true;

and 

> 'keystone_authtoken/admin_user' :                value => 'admin';
> 'keystone_authtoken/admin_password':             value => $admin_password, secret =>true;

hard-coded user name. 

Similar things are observed in `manifests/plugins/opencontrail.pp`, for `$keystone_admin_user, $keystone_admin_tenant_name,$keystone_admin_password, $keystone_admin_token` in `neutron_plugin_opencontrail {}` 

Similar things happen in `manifests/plugins/nvp.pp`, for `$nvp_user, $nvp_password,` in `neutron_plugin_nvp {}`

Similar things happen on `manifests/plugins/nuage.pp` for `$nuage_vsd_username, $nuage_vsd_password,` in `'RESTPROXY/serverauth': value => "{nuage_vsd_username}:${nuage_vsd_password}";`

Similar things happen in `manifests/plugins/nsx.pp`, for `$nsx_api_user, $nsx_api_password` in `neutron_plugin_nsx {}`

Similar things happen in `manifests/plugins/midonet.pp`, for `$keystone_username, $keystone_password` in `neutron_plugin_midonet {}`

Similar things happen in `manifests/plugins/cisco.pp` for 
- `$database_user, $database_pass` in `neutron_plugin_cisco_db_conn {}`
- `$keystone_username, $keystone_password, $keystone_auth_url` in `neutron_plugin_cisco_credentials {}`

Similar things happen in `manifests/server/notifications.pp`, for `$auth_url, $username, $password` in `neutron_config {}`

Similar things happen in `manifests/server/placement.pp`, for `$auth_url, $username, $password` in `neutron_config {}`

Similar things happen in `manifests/services/lbaas/octavia.pp`, for `$base_url, $auth_url, $admin_user, $admin_password` in `neutron_config {}`

Similar things happen in `manifests/wsgi/api.pp`, for `$ssl_cert, $ssl_crl_path` in `::openstacklib::wsgi::apache {}`

Similar things happen in `manifests/rootwrap.pp`, for `$xenapi_connection_username, $xenapi_connection_password` in `:neutron_rootwrap_config {} `

###### Slightly unrelated: `$quota_firewall_policy,$$quota_router,$quota_security_group_rule,$quota_firewall_rule `  need to see this flows to and from `manifests/quota.pp` ... later used in `neutron_config {}`

Similar things happen in `manifests/init.pp` for `$amqp_username, $amqp_password` in `oslo::messaging::amqp {}`
Similar things happen in `manifests/init.pp` for `$kombu_ssl_certfile, $kombu_ssl_keyfile` in `oslo::messaging::rabbit {}`
Similar things happen in `manifests/designate.pp`, for `$auth_url, $username, $password` in `neutron_config {}`

##### Tracking data 

1. `examples/neutron.pp`: `password => 'secrete',` in `class { '::neutron::server::notifications':` calls `manifests/server/notifications.pp` with `password` that flows into `neutron_config {}` 

2. `examples/cisco_ml2.pp`: 
```
class {'::neutron::plugins::ml2::cisco::ucsm':
  ucsm_username  => 'admin',
  ucsm_password  => 'password',
}  
```
calls `manifests/plugins/ml2/cisco/uscm.pp` with `ucsm_username` and `ucsm_password` that flows into ` neutron_plugin_ml2 {}` 

3. In `manifests/plugins/ml2/cisco/uscm.pp` 

```
  nexus_config             => {
    'n9372-1' => {
      'username'     => 'admin',
      'password'     => 'password',
    },
    'n9372-2' => {
      'username'     => 'admin',
      'password'     => 'password',
    }, 
  }
```

`username` and `password`  flows within `$nexus_config,` into `class neutron::plugins::ml2::cisco::nexus(){}` in `manifests/plugins/ml2/cisco/nexus.pp`


#### Example-11 

1. Location:`/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/fuel-plugin-ceilometer-redis-2018-06/deployment_scripts/puppet/modules/redis/tests/init.pp`, `conf_bind => '0.0.0.0'`, used in `init.pp` is used no where ... this is a false positive 

#### Example-12

Location:`/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/puppet-monasca-2018-06/` 

1. In `manifests/vertica/config.pp`,  `$db_admin_password` is declared but not assigned, so this will be a FP 

2. In `manifests/vertica/config.pp`,  `$db_user` is declared and used inside `file {}`, using `owner  => $db_user,` 

3. In `manifests/storm/config.pp`,  `$mirror = 'http://apache.arvixe.com/storm',` is used in `wget::fetch { "${mirror}/${storm_version}/${tarfile}": }`

4. In `manifests/storm/config.pp`,  `$storm_user` is used in `storm_user => $storm_user` and `user { $storm_user:` and `owner => $storm_user,` and `exec { "tar -xvzf /${cache_dir}/${tarfile}":`

5. In `manifests/storm/config.pp`,  `$storm_user` is declared but not assigned, so this will be a FP  

6. In `manifests/persister/config.pp`,  `$db_admin_password` is declared but not assigned, so this will be a FP  

7. In `manifests/keystone/auth.pp`, `$role_user` is used in `keystone_role { }` and `$real_user_roles_user = [$role_user]` 

8. In `manifests/influxdb/bootstrap.pp`, `$influxdb_password` and `$influxdb_dbuser_ro_password` is used in `exec { "/tmp/${script}": environment => []}` 

9. In `manifests/db/mysql.pp`, `$sql_password` is used in `mysql::db { 'mon':}` which is a true positive 
and in `password_hash => mysql_password($sql_password),` si a false positive 

10. In `manifests/checks/instances/solidfire.pp`, `$admin_password` and `$admin_password` is declared but not used in so this is a false positive 

11. In `manifests/checks/instances/rabbitmq.pp`, `$rabbitmq_user` and `$rabbitmq_pass` is declared but not used in so this is a false positive 

12. In `manifests/checks/instances/mysql.pp`, `$user` and `$pass` is declared but not used in so this is a false positive 

13. In `manifests/checks/instances/http_check.pp`, `$username` and `$password` is declared but not used in so this is a false positive 

14. In `manifests/checks/vertica.pp`, `$user` and `$password` is declared but not used in so this is a false positive  

15. In `manifests/checks/ovs.pp`, `$admin_user` and `$admin_password` is declared but not used in so this is a false positive  

16. In `manifests/checks/libvert.pp`, `$admin_user` and `$admin_password` is declared but not used in so this is a false positive  

17. In `manifests/checks/libvert.pp`, `$admin_user` and `$admin_password` is declared but not used in so this is a false positive  

18. In `manifests/thresh.pp`, `$thresh_fetch_url` is used in `wget::fetch { "${thresh_fetch_url}/${mon_thresh_build_ver}/${mon_thresh_deb}":}` 

18. In `manifests/persister.pp`, `$db_admin_password` is declared but not used and  `pers_fetch_url` is used in `wget::fetch { "${pers_fetch_url}/${mon_pers_build_ver}/${mon_pers_deb}":`

19. In `manifests/params.pp`, `$agent_password`, `$admin_password`, `$admin_name`, `$user_name` is declared but not used ... `database_url` is a true positive 

20. In `manifests/notification.pp`, `$smtp_password` and `$smtp_user` is declared but not assigned, so FP 

21. In `manifests/api.pp`, `$api_user` is used in `owner => $api_user,` and ` user { $api_user:}`

22. In `manifests/alarmdefs.pp`, `$admin_username` and `$admin_password` is used in `environment => []`

23. In `manifests/agent.pp`, `$password` and `$username` is declared but not assigned, so FP 

#### Example-12

Location: ``

> $mysql_opts = hiera('mysql')
> $mysql_password = $mysql_opts['root_password']
> $sql_connect = "mysql -h ${galera_host} -uroot -p${mysql_password}"
... 
> $sql_query = "${sql_connect} -e \"${db_query}; ${table_query}; ${update_query};\""

Even though there is a SQL-injection like statement, the value is not hard-coded rather coming
from hiera(). This should not be flagged. 


#### Example-12

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

#### Example-13

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


#### Example-14

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