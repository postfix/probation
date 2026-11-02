# Policy

Policy decides which npm and PyPI versions a client can see or download. A block can stop a whole package, one version, or one exact file. A release delay hides versions until they are old enough. The OSV check uses reports of known vulnerabilities. Passing these checks does not prove a package is safe.

## Standalone

The firewall reads `cooldown_seconds` and `osv_mode` from `config.toml`. The sample holds releases for 24 hours and blocks OSV matches. It reads blocks from the file named by `blocklist_file`; [`blocklist.sample.json`](../blocklist.sample.json) shows the format.

Check a replacement file with `probation check-blocklist /etc/probation/blocklist.json` before putting it in place. The firewall reloads the blocklist while running. Changes to `config.toml` need a restart.

Standalone mode has no per-package exception control. To allow a blocked package, remove its block from the JSON file and replace the live file. To release a frozen package early, lower `cooldown_seconds` for all packages and restart, or use managed mode for a package-specific exception.

## Managed

Sign in, choose a **Place**, and open **Policy**. Rules can come from four levels:

| Level | Who changes it |
| --- | --- |
| Platform | Global admin |
| Organisation | Org admin |
| Group | Org admin or that group's admin |
| Member or personal account | Its owner; an org admin can also change a member's rules |

The page's **Layers** links show what you may open. **Chain** shows where the current rules come from. A lower level can always make a rule stricter. It can loosen an inherited rule only when the higher levels allow it.

To hold new releases, set **Hold new versions for** in hours or days and press **Save changes**. To check known vulnerabilities, choose **On: block them**, **Log only**, or **Off** under **OSV malicious-package check**. An empty freeze value or **Inherit** takes the setting from above. A new organisation starts without an age delay or OSV check; set these explicitly if you need them.

To stop a package, use **Blocks → Add a block**. Choose npm or PyPI, then **Whole package**, **One version**, or **One exact file**. For a file, enter its SHA-256 or SHA-512 digest. The table shows who set each block; you can remove only blocks on a level you may edit.

## Allow one package or version

1. Sign in, choose the **Place** that will install the package, open **Policy**, and select a layer you can edit.
2. Under **Exceptions → Add an exception**, choose **npm** or **PyPI** and enter the exact **Package name**. To allow only one release, fill in **Exact version** (for example, `1.2.3`). Leave it empty to cover the whole package, including future versions.
3. Under **Let it through**, tick **Blocklist** to bypass a block, **Freeze** to allow a new version before its age delay ends, or **OSV** to bypass a vulnerability match. Tick only the checks you intend to lift, then press **Add exception**.
4. Find the new row in **Exceptions**. If it says **not in effect**, ask the administrator of the higher layer to allow the relevant change: **Allow package exceptions** for a block, **Allow a shorter freeze** for an age delay, or **Allow turning OSV off** for an OSV result. Every layer between that rule and your exception must allow it. You can also ask the owner of the block to remove it.
5. Wait for the next firewall sync (normally within one minute), try the package again, and check **Activity**.

For example, to install only npm `example-package` version `1.2.3` while it is frozen, enter that name and version and tick **Freeze**. To allow a package blocked by name, tick **Blocklist**; leave the version empty only if all its versions should be allowed. An exception lifts only the checks you tick, so a still-frozen package can remain held after you lift its block.

For each switch and exception rule, see the [full policy reference](portal-guide.md#38-policy).
