'''
Akond Rahman 
Jan 27, 2020 
'''

## Notes from exploring Ansible repos 

> Repo: /Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/openshift@openshift-ansible-contrib 

1. Default port in misc/gce-federation/files/pacman-service.yaml, misc/gce-federation/files/pacman-rs.yaml, and misc/gce-federation/files/mongo-service.yaml, and misc/gce-federation/files/mongo-rs.yaml, and and misc/gce-federation/files/mongo-deployment-rs.yaml   
2. Legit invalid IP address in misc/gce-federation/files/init.yaml 


> Repo: /Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/redhat-performance@satellite-performance/ 

1. All TPs in /Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/redhat-performance@satellite-performance/playbooks/satellite/satutils.yaml 
2. hard-coded secrest from `conf/satperf.yaml` propagates into `playbooks/satellite/satutils.yaml`
3. if no reachable path is found for `{{ varX }}`, then  a FP 
4. `become_user` is used for privilege escalation in /Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/redhat-performance@satellite-performance/playbooks/experiments/roles/pg_remote_db_populate/tasks/main.yaml  
5. TP hard coded usernames in /Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/openshift@openshift-ansible-contrib/reference-architecture/vmware-ansible/playbooks/cleanup-crs.yaml 
6. `url:` in /Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/openshift@openshift-ansible-contrib/reference-architecture/vmware-ansible/playbooks/roles/heketi-install/tasks/main.yaml is an example of insecure HTTP and default port ... but `ansible_default_ipv4.address` comes from command line if a file is not included 

> Notes on variables: https://docs.ansible.com/ansible/latest/user_guide/playbooks_variables.html 


>  Other important notes 

1. FP in /Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/openshift@openshift-ansible-contrib/playbooks/openstack/openshift-cluster/files/heat_stack_server.yaml 

2. TP, invalid IP in /Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/openshift@openshift-ansible-contrib/playbooks/openstack/openshift-cluster/files/heat_stack.yaml and /Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/openshift@openshift-ansible-contrib/reference-architecture/3.9/playbooks/roles/aws/tasks/routetablerule.yaml and `/Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/carlosthe19916@openshift-ansible/playbooks/openstack/openshift-cluster/files/heat_stack.yaml` 

3. Default port and other TPs in /Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/laincloud@lain/playbooks/roles/config/defaults/main.yaml 
4. `sat_user` and `sat_pass` in `/Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/redhat-performance@satellite-performance/conf/satperf.yaml` , are propagated into `/Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/redhat-performance@satellite-performance/playbooks/tests/puppet-setup.yaml` in `vars_files:`, which is used in `command:`

5. FP hard-coded key in /Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/laincloud@lain/playbooks/roles/bootstrap-etcd/tasks/main.yaml  and /Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/openshift@openshift-ansible-contrib/playbooks/openstack/openshift-cluster/files/heat_stack_server.yaml 

6. TP hard-coded password in `/Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/openshift@openshift-ansible-contrib/reference-architecture/3.9/playbooks/vars/main.yaml` is later used in `/Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/openshift@openshift-ansible-contrib/reference-architecture/3.9/playbooks/roles/aws/tasks/sshkeys.yaml` in `name: "{{ 'Generate' if (state is undefined or 'absent' not in state) else 'Terminate' }} clusterid SSH key"` 

7. FP hard-coded secret in `/Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/openshift@openshift-ansible-contrib/reference-architecture/aws-ansible/playbooks/roles/non-atomic-docker-storage-setup/tasks/main.yaml` 

8. FP hard-coded key in /Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/openshift@openshift-ansible-contrib/reference-architecture/gcp/ansible/playbooks/roles/ssl-certificate/tasks/main.yaml and /Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/openshift@openshift-ansible-contrib/reference-architecture/vmware-ansible/playbooks/roles/docker-storage-setup/tasks/main.yaml and /Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/mcapuccini@KubeNow/playbooks/roles/nginx/templates/nginx-config.yaml and /Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/openebs@openebs/e2e/ansible/playbooks/hyperconverged/test-k8s-drain-nodes/replica_patch.yaml 

9. Default port, FN for HTTP, 1 FP for hard-coded user name in /Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/openshift@openshift-ansible-contrib/reference-architecture/vmware-ansible/playbooks/roles/haproxy-server-config/defaults/main.yaml and /Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/openshift@openshift-ansible-contrib/reference-architecture/vmware-ansible/playbooks/roles/haproxy-server/defaults/main.yaml 

10. FP empty password in /Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/d34dh0r53@os-ansible-deployment/playbooks/roles/os_heat/files/templates/AWS_RDS_DBInstance.yaml 

11. In general I think that if a password is not associated a task, then it is a FP 

12. FP hard coded key in /Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/kubenow@KubeNow/playbooks/roles/nginx/templates/nginx-config.yaml 

13. FP hard-coded key and FN `http` in /Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/laincloud@lain/playbooks/roles/calico/tasks/main.yaml 

14. FP hard-coded secret in /Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/laincloud@lain/playbooks/roles/node-change-labels/tasks/main.yaml 

15. Default port in /Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/openshift@openshift-ansible-contrib/reference-architecture/aws-ansible/playbooks/openshift-setup.yaml and `/Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/redhat-performance@satellite-performance/playbooks/common/roles/common/tasks/main.yml` 

16. FP hard-coded secret in /Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/openshift@openshift-ansible-contrib/reference-architecture/gcp/ansible/playbooks/roles/ssl-certificate-delete/defaults/main.yaml and /Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/openshift@openshift-ansible-contrib/reference-architecture/gcp/ansible/playbooks/roles/ssl-certificate/defaults/main.yaml and /Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/openshift@openshift-ansible-contrib/reference-architecture/vmware-ansible/playbooks/roles/cloud-provider-setup/tasks/main.yaml and /Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/openshift@openshift-tools/ansible/playbooks/adhoc/metrics_setup/files/metrics.yaml and /Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/redhat-performance@satellite-performance/playbooks/common/roles/scalelab-nic-cleanup/tasks/main.yaml and /Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/redhat-performance@satellite-performance/playbooks/containerized/roles/install-openshift-oc/tasks/main.yaml  and /Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/redhat-performance@satellite-performance/playbooks/docker/docker-purge-storage.yaml 

17. FP hard-coded secret and default password in /Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/openshift@openshift-ansible-contrib/reference-architecture/vmware-ansible/playbooks/ocp-install.yaml 

18. `../common/roles/rhsm/tasks/main.yml` has a default port that is propagated in `/Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/redhat-performance@satellite-performance/playbooks/common/prepare_host.yaml` with `roles:` 

19. Default port usage in `/Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/redhat-performance@satellite-performance/playbooks/common/roles/common/tasks/main.yaml` and `/Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/redhat-performance@satellite-performance/playbooks/kvm-hosts/install-vms.yaml` and `/Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/openshift@openshift-ansible-contrib/reference-architecture/gcp/ansible/playbooks/openshift-post.yaml` and `/Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/redhat-performance@satellite-performance/playbooks/common/roles/rhsm/tasks/main.yaml` 

20. hard-coded user name TP in `/Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/redhat-performance@satellite-performance/playbooks/containerized/install.yaml`, also fun fact `roles:` refer to roles in the `roles` directory 

21. `katello_password` in `/Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/redhat-performance@satellite-performance/playbooks/experiments/satellite_remote_db.yaml` is used in `vars_files` so TP 

22. `/Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/redhat-performance@satellite-performance/playbooks/kvm-hosts/check.yaml` and /Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/redhat-performance@satellite-performance/playbooks/kvm-hosts/host.yaml and `/Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/redhat-performance@satellite-performance/playbooks/kvm-hosts/install-vms.yaml` and `/Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/redhat-performance@satellite-performance/playbooks/monitoring/grafana.yaml` and `/Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/redhat-performance@satellite-performance/playbooks/monitoring/dashboards-generic.yaml` and `/Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/redhat-performance@satellite-performance/playbooks/monitoring/graphite.yaml` and `/Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/redhat-performance@satellite-performance/playbooks/satellite/remove-satellite.yaml` uses `var_files` that include `../../conf/satperf.yaml` that has hard-coded secrets ... but they need to be used in the current script or in a referenced role.  

23. FN hard-coded user name in `/Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/redhat-performance@satellite-performance/playbooks/satellite/ec2-cleanup.yaml`

24. `/Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/redhat-performance@satellite-performance/playbooks/satellite/satellite-remove-hosts.yaml` uses `sat_pass` declared in `../../conf/satperf.yaml` and imported by `var_files` 

25. `/Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/redhat-performance@satellite-performance/playbooks/satellite/client-scripts.yaml` uses `var_files` where `../../conf/satperf.yaml` is declared that is later used in `client-scripts`, which is used in `/Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/redhat-performance@satellite-performance/playbooks/satellite/roles/client-scripts/tasks/main.yml`, so TP. Simialr propagation for `/Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/redhat-performance@satellite-performance/playbooks/satellite/capsules.yaml` as well where imported `var_files` goes into a role.  Simialr things happen in `/Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/redhat-performance@satellite-performance/playbooks/satellite/satellite-populate.yaml` and `/Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/redhat-performance@satellite-performance/playbooks/soak-tests/daily-cv-ops.yaml` and `/Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/redhat-performance@satellite-performance/playbooks/soak-tests/rex-job.yaml` and `/Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/redhat-performance@satellite-performance/playbooks/soak-tests/errata-apply.yaml` and `/Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/redhat-performance@satellite-performance/playbooks/soak-tests/content-view-promote.yaml` and `/Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/redhat-performance@satellite-performance/playbooks/soak-tests/content-setup.yaml` and `/Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/redhat-performance@satellite-performance/playbooks/soak-tests/sync-plan.yaml`.      

26.  In `/Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/redhat-performance@satellite-performance/playbooks/tests/rex.yaml` hard-coded secrets propagate from `../../conf/satperf.yaml` used as `var_files` into `name: "Start the 'date' job '{{ job_desc }}'"`. Simialr things happen for `/Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/redhat-performance@satellite-performance/playbooks/tests/sync-repositories.yaml` and `/Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/redhat-performance@satellite-performance/playbooks/tests/puppet-big-setup.yaml` and `/Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/redhat-performance@satellite-performance/playbooks/tests/hammer-list.yaml` and `/Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/redhat-performance@satellite-performance/playbooks/tests/puppet-single-setup.yaml` and `/Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/redhat-performance@satellite-performance/playbooks/tests/continuous-rex.yaml` and `/Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/redhat-performance@satellite-performance/playbooks/tests/puppet-big-test.yaml`

27. FP empty password in `/Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/openshift@openshift-ansible-contrib/reference-architecture/azure-ansible/3.5/ansibledeployocp/playbooks/roles/azure-deploy/tasks/main.yaml` and `/Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/openshift@openshift-ansible-contrib/reference-architecture/azure-ansible/3.6/ansibledeployocp/playbooks/roles/azure-deploy/tasks/main.yaml` 

28. TP `no integrity check` in `/Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/openshift@openshift-ansible-contrib/reference-architecture/azure-ansible/3.5/ansibledeployocp/playbooks/roles/prepare/tasks/main.yaml` and `/Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/openshift@openshift-ansible-contrib/reference-architecture/azure-ansible/3.6/ansibledeployocp/playbooks/roles/prepare/tasks/main.yaml` and `/Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/redhat-performance@satellite-performance/playbooks/katello/roles/add_katello_repos/tasks/main.yaml` 

29. A string that starts with the word `vault` is a secret stored using Vault, so probably a FP. Example : 
> db_password: {{ vaulted_db_passord }}
> Reff: https://titanwolf.org/Network/Articles/Article?AID=c096dd39-fc98-48c2-ac9c-7ecec1e0e125#gsc.tab=0

Need to check of vault file is encrypted or decrypted, if decrypted then will look like this 
```
# vault_file
vaulted_db_passord: a_super_secret
vaulted_aws_secret_access_key: the_aws_secret
```

30. This article (https://www.cyberark.com/resources/blog/securely-automate-it-tasks-with-ansible-and-cyberark) says:

```
Ansible Playbooks are highly privileged. To access, manage and configure IT resources – such as a VM, server or cloud compute instance – playbooks require appropriate credentials and secrets. If these powerful privileged credentials are not properly managed and secured – or left hardcoded in playbooks or scripts – they become attractive targets for attackers.
```

Is it possible to get this ^ ? 

