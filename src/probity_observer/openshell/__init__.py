"""Read NVIDIA OpenShell and NemoClaw artifacts as declarations and as a second vantage.

OpenShell enforces (Landlock, seccomp, an L7 proxy); the observer records and signs. This
package takes four things from the enforcer without trusting it: the declared network policy
(:mod:`.policy`), its seccomp block list (:mod:`.seccomp`), its OCSF event stream as an
enforcer-side claim (:mod:`.ocsf`), and its policy prover's containment verdict
(:mod:`.prover`). The pinned upstream versions and digests are in :mod:`.pins`.
"""
