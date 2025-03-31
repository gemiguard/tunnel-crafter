# Script Issues


## Script doesn’t exit immediately if not ran as root

### Issue

Script doesn’t exit immediately if not ran as root causing error and termination later.

### Diagnosis

Invocation of the `error()` function at line 29 fails when user is not
root because the log file cannot be appended due to permissions, so the
`exit` is never reached.

### Fix

Instead of calling `error()` when user is not root, just output error
message and quit.

```shell
$ ./vps.sh 
[-] This script must be run as root
$
```

## No network check.

### Issue

No network check. Not a big deal but if there are issues with DNS the check would catch them.

### Fix

Added network connectivity check by pinging defined IP address (environment
variable `$PING_TEST_IP`).  Three pings sent with 5 second timeout, aborts
with error if fails.

```shell
test_network() {
  log "Testing network connectivity (to ${PING_TEST_IP})"
  ping -c3 $PING_TEST_IP -W5 >&/dev/null
  if [[ $? -eq 0 ]]; then
    log "Network connectivity OK"
  else
    error "Network connectivity test to ${PING_TEST_IP} failed"
  fi
}
```

## User Input

### Issue

There is user-input requirement during the system upgrade, most/all could be avoided.

### Diagnosis

I'm not sure what this means - the script is designed to take user input,
so changing that would probably require a rewrite of the script?

(Using a script like this for automated configuration of a system is
not good practice anyway, it would be better to adopt an Infrastructure
As Code approach using something like Ansible if unattended automated
configuration is desired)

## Netdata throws an error if ran as root

### Issue

Netdata throws an error if ran as root (default VPS configuration only has the root user).

### Diagnosis

I cannot find such an error.  Are there more specific details available?

## Netdata - missing /dev/fd

### Issue

Netdata - missing /dev/fd - from what I can tell the error has no real implications

### Diagnosis

This is an issue with the netdata script, which we have no control over.

## Netdata - cloud cannot be disabled 

### Issue

Netdata - cloud cannot be disabled - have to look into this one, but Netdata seems to be working fine.

### Diagnosis

VPS script was invoking the netdata install script with the `--disable-cloud`
option. When that option is given, the netdata install script emits a warning
saying it is not possible to disable cloud.

### Fix

Remove `---disable-cloud` option from invocation of netdata install script.

## WGDashboard is not started

### Issue

WGDashboard is not started due to the missing net-utils package.

### Diagnosis

On my test installs WGDashboard is listening on port 10086.

```shell
# netstat -tulpen | grep 10086
tcp        0      0 0.0.0.0:10086           0.0.0.0:*               LISTEN      0          57604      42688/python3       
```

## Root SSH access

### Issue

Root SSH access is disabled by the script and replaced with the admin user, however public key is required for the authentication which requires manual intervention. Could add user public key to script.

### Comment

I could hard-code a specific public key into the script or give the user
the opportunity to paste one in during installation.

Need clarification on how to proceed with this.

## Wireguard client QR code can get corrupted 

### Issue

Wireguard client QR code can get corrupted, happened first time when I ran the script.

### Diagnosis

The Wireguard client QR code was generated successfully in my tests.

## Netdata Dashboard Authentication 

### Issue

Netdata dashboard is accessible to the internet without any authentication by default.

### Comment

I can easily add HTTP basic authentication (login/password) via NGINX to either or
both wg dashboard / netdata.  Please advise.

## Subdomains

### Issue

All sub-subdomains end up at Netdata

### Diagnosis

I don't have sufficient detail to understand or find the problem.

Netdata is running, and I can't find any issues in its output.  Further details?
