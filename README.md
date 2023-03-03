# Running ntopng Natively On The Unbiquiti Dream Machine Pro (UDM-Pro)

With the release of Unifii OS v2.4.27 on UDM Pro devices, ntopng can now be run natively on the UDM.  A podman container is no longer required.

The Debian packages generated by the script in this repository support running the ntopng network traffic analyzer natively on a Ubiquiti Dream Machine Pro.  These packages are distribued through a PPA repository that can be used by the `apt` command on the UDM to install ntopng.  See [this page](https://dlk3.github.io/udm-hacks-repo/README.ntopng.html) for information on installing ntopng on the UDM.
