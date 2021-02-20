# Auxiliary docs

These items are not required to use the scripts as it goes a bit beyond the
original project intention of sandboxing based on a signed-in user, but these
are some tips and tricks for external support items that may aid in usage and
testing to reach the overall goal of securing the system as desired.


## Test methods
Some additional ways to confirm the setup is working as desired, all of which
can be prefaced with `sudo -u <myser>` to run as that user:
- `curl https://ipleak.net/json/` and check details.  See
      [here](https://airvpn.org/forums/topic/14737-api/) for more details.
- `dig +short myip.opendns.com @resolver1.opendns.com` or
      `curl checkip.amazonaws.com` and check IP address as expected
- `ip netns identify <pid>` to print the network namespace that process is
using, or blank if not using one
- `ip netns list-id` to list all network namespace IDs (including ones from
      outside this project)
- `ip route list` will list the routing table.
- `ip -n <myuser> route` will list routing table in namespace.
- `daemon --name="socat-<myuser>" --running -v` will check if a daemon is
      running for socat in the event a port number was provided.
  - Will report "daemon:  socat-<myuser> is running (pid 751816)" or
        "daemon:  socat-<myuser> is not running"
- `ip netns exec <myuser> nc -ln <ip-addr-of-interface> <any-port> -v` can be
      started, then `nc -4tn <same-ip-addr> <same-port> -v` to connect and send
      messages to test connectivity established with socat.
  - The `<ip-addr-of-interface>` should be the one assigned to the veth
        interface when created in the `init` script when providing a port.
  - Can use any port number, not just the one used in `init`.
- `curl -Is <localhost-or-ip>:<port> | head -1` can be used to check http
      response to test connectivity (if no response, nothing returned).
- `ip netns exec <myuser> tcpdump -X -i <wgifname> -n tcp -l` and other variations
      of `tcpdump` (e.g. `tcpdump -i br0-mullvad - nne` to monitor the bridge)
      may be helpful for monitoring traffic, especially with the bridge setup.
- [This](https://torguard.net/checkmytorrentipaddress.php) is a helpful way to
      test.  Note that it often takes awhile for the IP address to show both on
      the site and in the client.


## Other dependent services requiring netns
Sandboxing a service in a network namespace may not work simply be setting the
`User=` in the service file, at least based on preliminary testing in Ubuntu
20.04.  Luckily, with systemd 452 and later, there is a second option.

By editing the service file with `systemctl edit --full <name-of-service>`, the
line `NetworkNamespacePath=/var/run/netns/<myuser>` can be added in the
`[Service]` section.  After a reload and a restart of the service, it will now
be operating in that network namespace.  The service should also fail to run if
the network namespace does not exist, but best to test that failsafe.

If the netns is deleted and recreated, the service likely needs to be restarted.


## Create and teardown at boot and shutdown using systemd service
The creation can be automated to run on boot through automated means, as well as
the teardown when shutting down.  It is not likely teardown is needed explicitly
when shutting down, but it is added here in case it is useful either through
manual invocation or an unknown benefit of doing it explicitly.

Many common Ubuntu means can be used for this purpose.  In the past `rc0.d` and
`rc6.d` may have worked (similar to [this](https://askubuntu.com/a/416330) but
with an `s*` script for `rc0.d`), but systemd is now recommended.

Another option is `sudo crontab -e` (since need to run as root) and using
`@reboot` instead of the usual time/calendar parameters at the start of the
line.

For systemd, if unfamiliar, something like the following could work to create:
```
    $ sudo nano /etc/systemd/system/mullvad-netns-create.service

### Add the following within the file ###
[Unit]
Description=Create mullvad netns

[Service]
Type=oneshot
ExecStart=/path/to/mullvad-ubuntu/mullvad-wg-netns.sh init <rest-of-init-opts>

[Install]
WantedBy=multi-user.target

### Save file ###

    $ sudo systemctl daemon-reload
    $ sudo systemctl enable mullvad-netns-create.service

    # When want to start
    $ sudo systemctl start mullvad-netns-create.service
```

And to teardown (untested, might need some adjustment):
```
    $ sudo nano /etc/systemd/system/mullvad-netns-teardown.service

### Add the following within the file ###
[Unit]
Description=Teardown mullvad netns
After=final.target

[Service]
Type=oneshot
ExecStart=/path/to/mullvad-ubuntu/mullvad-wg-netns.sh del <rest-of-del-opts>

[Install]
WantedBy=final.target

### Save file ###

    $ sudo systemctl daemon-reload
    $ sudo systemctl enable mullvad-netns-teardown.service

    # When want to run manually right now
    $ sudo systemctl start mullvad-netns-teardown.service
```

A better way, though, may be to combine them and leave the service "running"
between being created and destroyed even though it does nothing in between:
```
    $ sudo nano /etc/systemd/system/mullvad-netns.service

### Add the following within the file ###
[Unit]
Description=Create and destroy mullvad netns

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/path/to/mullvad-ubuntu/mullvad-wg-netns.sh init <rest-of-init-opts>
ExecStart=/path/to/mullvad-ubuntu/mullvad-wg-netns.sh init <rest-of-2nd-init-opts>
ExecStart=/path/to/mullvad-ubuntu/mullvad-wg-netns.sh init <rest-of-3rd-init-opts>

ExecStop=/path/to/mullvad-ubuntu/mullvad-wg-netns.sh del <rest-of-del-opts>
ExecStop=/path/to/mullvad-ubuntu/mullvad-wg-netns.sh del <rest-of-2nd-del-opts>
ExecStop=/path/to/mullvad-ubuntu/mullvad-wg-netns.sh del <rest-of-3rd-del-opts>


[Install]
WantedBy=multi-user.target

### Save file ###

    $ sudo systemctl daemon-reload
    $ sudo systemctl enable mullvad-netns.service

    # When want to start
    $ sudo systemctl start mullvad-netns.service
    # When want to stop
    $ sudo systemctl stop mullvad-netns.service
```

If using the separate service files, extra options can be added to start and
stop as well using `ExecStart`.

Regardless, it may be preferable if used with other services that rely on the
netns to be modified to link to these.  For example, one way may be to add the
following to the `[Unit]` section of the service file that relies on the netns:
```
Requires=mullvad-netns.service
PartOf=mullvad-netns.service
```
Alternatively, a stronger way may be add the following instead to that same file
and section:
```
BindsTo=mullvad-netns.service
After=mullvad-netns.service
```

The former will link the starting and stopping; the latter will ensure the
service depending on the netns will never be in an active state unless the
`mullvad-netns.service` is also active.  This may be helpful to ensure that
stopping the netns and possibly breaking the VPN connection will ensure that the
other services depending on it are stopped to avoid leaking traffic.  This does
mean the other service would need to be restarted manually.

Of course, in all of these cases, a script could be created and provided as the
arg to `ExecStart=` and `ExecStop=`.  Don't forget the `chmod +x <script>`.


## Running commands as another user in a namespace without root
Ok, it involves root, but only at install time, not at invocation time.

The `firejail` application can be used to run commands in another network
namespace, but please understand the **RISKS**.  From
[firejail's docs](https://firejail.wordpress.com/documentation-2/basic-usage/):
```
We use this [SUID] Linux feature to start the sandbox, since most kernel
technologies involved in sandboxing require root access. Once the sandbox is
installed, root permissions are dropped, and the real program is started with
regular user permissions.
```

With those risks accepted, most likely in a single user environment, it can be
installed and configured:
```
# Install
sudo apt-get install firejail

# Backup config defaults
sudo cp /etc/firejail/firejail.config /etc/firejail/firejail.config.default

# Edit the config
sudo nano /etc/firejail/firejail.confg
  - Change "# network yes" to "network yes" (uncomment)
  - Change "restricted-network yes" to "restricted-network no"
```

Once installed and configured, commands can be run with:
```
firejail --noprofile --netns=<myuser> <cmd>
```
Optionally, `--quiet` can also be specified between `firejail` and `<cmd>` to
suppress firejail's messages about parent and child processes, etc. in order to
provide output as if the command were run normally, just in a different network
namespace.
