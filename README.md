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

    $ path/to/mullvad-wg-net.sh init <myuser> mullvad-<regioncode>.conf

Replace `<regioncode>` by whatever mullvad region you want to use, for example
`mullvad-at1.conf`, you can find the full list in `/etc/wireguard/` after
provisioning.

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
