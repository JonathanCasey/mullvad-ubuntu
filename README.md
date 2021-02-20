wireguard mullvad network namespace wrapper
===========================================

Overview
--------

Based on DanielG/dxld-mullvad with updates from Kagee/kagee-mullvad (big
thanks! :tada:).

A fantastic way to get certain apps/scripts/processes to use the VPN while
defaulting the rest of the system to not using the VPN.  Perfect when only want
select traffic going over VPN rather than only select traffic bypassing VPN
(i.e. blacklist instead of whitelist) without having to mess with existing ip
tables.  No other installation required (including mullvad's installer).

[`mullvad-wg-netns.sh`](mullvad-wg-netns.sh) implements the provisioning of the
wireguard configs (generating privkey, uploading pubkey to mullvad API etc.). It
also supports bringing up the wireguard interface at boot since `wg-quick` does
not support netns or operating on a pre-existing wg interface.

Setup on Ubuntu (20.04 focal)
---------------------

First we set up dependencies and libpam-net:

```
    $ apt-get install dateutils curl jq linux-headers-$(uname -r) wireguard-dkms wireguard-tools
```

Note we need at least libpam-net 0.3.  `libpam-net` looks to be added to Ubuntu
in the upcoming 21.04 (hirsute) release as seen
[here](https://packages.ubuntu.com/hirsute/libpam-net).  If you are lucky,
default apt `sources.list` list in 20.04 should allow the following:
```
    $ apt-get udpate
    $ apt-get install libpam-net/focal-backports
```

If unlucky like at the time of this writing, it is not [yet] in backports.  An
alternative is to follow
[Ubuntu's Pinning Howto](https://help.ubuntu.com/community/PinningHowto), or to
install with the `.deb` from the link to the package above.  Personally, I
followed pinning since the dependencies looked clear at time of writing, then
removed `hirsute` from my `sources.list` to prevent any accidental updates (I
had some manually installed packages that were older in `focal` but newer in
`hirsute`, so `apt list --upgradeable | grep hirsute` /
`apt-get upgrade --dry-run` and `apt-cache policy <package-name>` showed they
wanted to be updated).

Once all dependencies are installed, the rest of the setup can continue:
```
    $ pam-auth-update --enable libpam-net-usernet
    $ addgroup --system usernet
    $ adduser <myuser> usernet
  or for dummy user:
    $ useradd -M -s /usr/sbin/nologin -G usernet <myuser>
  to add existing user to the group (without needing sign out):
    $ sudo usermod -a -G usernet <myyser>
    $ exec su -l $USER
```

Now whenever `<myuser>` logs in, or a service is started as them, it will
be placed in a netns (cf. ip-netns(8)) corresponding to their
username. This netns is created if it doesn't already exist, but the
intention is that you arrange for it to be setup during boot.

Next we provision the wireguard configs:

    $ path/to/mullvad-wg-net.sh provision

This will ask you for your mullvad account number, so keep that ready. What
this does is associate your mullvad account with the wg private key it
generates.

Note: The account number is not stored on the system after provisioning.

We're almost done, now we setup `resolv.conf` to prevent DNS leaks in the
netns:

    $ mkdir -p /etc/netns/<myuser>
    $ printf '%s\n' '# Mullvad DNS' 10.64.0.1 > /etc/netns/<myuser>/resolv.conf
    $ chattr +i /etc/netns/<myuser>/resolv.conf

I do `chattr +i` to prevent resolvconf from meddling with this config. I suppose
it would be possible just to change the resolvconf configuration to get it
seperated from the main system, but without changes it will just use the DNS of
the rest of the system.

Finally to start the mullvad wireguard interface you should use the following
command:

    $ path/to/mullvad-wg-net.sh init <myuser> mullvad-<regioncode>.conf [<portnum>] [--bridge]

Replace `<regioncode>` by whatever mullvad region you want to use, for example
`mullvad-at1.conf`, you can find the full list in `/etc/wireguard/` after
provisioning.

`<portnum>`, as denoted by the square brackets (not to be used when calling), is
optional and can be completely omitted.  It allows a single port to be mapped to
the host IP address for routing.  This DOES create a potential leak, so only use
if you understand and accept the **RISKS**.

The `--bridge` option (also accepts `--brg`, `--br`, `-b`), if specified after
the `<portnum>`, will create the virtual ethernet peer pair with the host-side
connected to a bridge.  All invocations of this script that use this option will
connect all of those network namespaces to the same bridge on the host side.
This will enable all network namespaces on this bridge to be able to talk to
each other via this route if needed.  Again, only use if you understand and
accept the **RISKS**.

To make this permanent you can simply put it in `/etc/rc.local` or create a
systemd unit or something if you insist.

For the especially paranoid that do not want endpoints that keep logs to be able
to cross-correlate your activity, using multiple connections with multiple IP
addresses on the same machine is very easy!

All that is required is to create a namespace for each separate connection using
a different username for each, and then be sure to use a different mullvad
server for each (e.g. `mullvad-at1.conf` for the first and `mullvad-at2.conf`
for the second).  No need to think about the wireguard keys, as the same one set
of keys generated when provisioning can be used for all.

Listing existing items configured through this script can be found by running:

    $ path/to/mullvad-wg-net.sh list

This will list the mullvad config files provisioned, namespaces setup, whether
or not the bridge is setup for 0 or more namespaces, and any socat daemons
running.

Namespaces can be unloaded through the delete command:

    $ path/to/mullvad-wg-net.sh del <myuser>

This will delete the namespace, remove any associated adapters, end any socat
daemons, and will also unload the bridge with its iptable rules if it is no
longer being used.  In place of `<myuser>`, the bridge options used in `init`
can also be used (e.g. `--bridge`, `-b`, etc.).  This is meant only as a last
resort if something unclean may have left the bridge dangling.  It only deletes
the bridge, though, so it may leave any adapters that were connected to it still
existing.


Security
--------

In order to make sure this whole setup work and to prevent leaks if
something fails I like to check if connectivity is going through mullvad on
login. The mullvad guys provide a convinient service for this:
https://am.i.mullvad.net and I wrote a convinient shell wrapper for it:
[am-i-mullvad.sh](am-i-mullvad.sh).

To use it put it in your `.bash_profile` or simmilar shell startup script:

    $ cat >> .bash_profile << EOF
    sh path/to/am-i-mullvad.sh || exit 1
    EOF

If we're not connected through mullvad it will print an error message and kill
the shell after a short timeout so you can still get access by Ctrl-C'ing the
script if needed.

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
- `ip netns exec vnet0 tcpdump -X -i <wgifname> -n tcp -l` and other variations
      of `tcpdump` (e.g. `tcpdump -i br0-mullvad - nne` to monitor the bridge)
      may be helpful for monitoring traffic, especially with the bridge setup.
- [This](https://torguard.net/checkmytorrentipaddress.php) is a helpful way to
      test.  Note that it often takes awhile for the IP address to show both on
      the site and in the client.


Other Uses
----------

This goes a bit beyond the original project intention of sandboxing based on a
signed-in user, but these are some tips that might be helpful to use together to
reach the overall goal of securing the system as desired.

### Services
Sandboxing a service in a network namespace may not work simply be setting the
`User=` in the service file, at least based on preliminary testing in Ubuntu
20.04.  Luckily, with systemd 452 and later, there is a second option.

By editing the service file with `systemctl edit --full <name-of-service>`, the
line `NetworkNamespacePath=/var/run/netns/<myuser>` can be added in the
`[Service]` section.  After a reload and a restart of the service, it will now
be operating in that network namespace.  The service should also fail to run if
the network namespace does not exist, but best to test that failsafe.

If the netns is deleted and recreated, the service likely needs to be restarted.


### Create and Teardown at Boot and Shutdown
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


### Running commands as another user in a namespace without root
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
