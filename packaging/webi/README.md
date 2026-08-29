# Webi upstream package

The `realmroot/` directory is the package contribution for
[`webinstall/webi-installers`](https://github.com/webinstall/webi-installers).
Copy it to the upstream repository root and add `realmroot` alphabetically to
the three package lists in `test/install.sh`, as required by upstream's
contribution guide.

The public `https://webi.sh/realmroot` and `https://webi.ms/realmroot` URLs do
not consume these files from the Realmroot repository. They become available
only after the package is merged upstream and Webi refreshes its deployed
release cache.
