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

## Upstream Beta validation request

When submitting these files upstream, ask a Webi maintainer to deploy the PR
candidate to Webi Beta before merge. The deployment is maintainer-controlled;
Realmroot does not publish or operate an alternate Webi origin.

After the candidate is deployed, smoke-test both release selectors on a clean
macOS or Linux account:

```console
curl -sS https://beta.webi.sh/realmroot@stable | sh
realmroot version
curl -sS https://beta.webi.sh/realmroot@0.4.2 | sh
realmroot version
```

Both installers must select the target-appropriate archive and verify it
against the selected GitHub release's `checksums.txt`. A successful Beta test
does not make the production URLs available; production use still begins only
after upstream merge and deployment.
