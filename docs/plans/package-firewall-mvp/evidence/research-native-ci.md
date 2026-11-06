# Native GitHub Actions feasibility

Research date: 2026-11-02. External documentation review only. No workflows, installations, builds, client tests, Docker pulls, or runtime probes were run. Existing repository workflow inventory was supplied separately and was not re-investigated.

## Bounded question and decision

Question: Can standard GitHub-hosted Linux/macOS/Windows runners provide native client runtime tests and Docker/OCI end-to-end pulls in this topology, and what limitations must the design keep explicit?

Decision: Which native-runtime acceptance claims are feasible for Linux/macOS/Windows local clients talking to a Linux-only policy server, and which Docker claims must remain unverified. This report does not select a CI architecture or action/YAML versions.

Stopping condition: Official GitHub documentation identifies native OS jobs, container/service-container restrictions, the distinction between Docker tooling and a usable daemon, and remaining macOS/Windows Docker gaps. Six official pages were examined; no broader search was needed.

Verdict: **ANSWERED for hosted-runner feasibility and limits; no runtime pass is claimed.** Native ordinary-process tests are feasible on all three OS families. Ubuntu has documented Docker Client and Server inventory. Neither a Windows runner label nor a macOS runner label establishes a usable Docker Desktop/Linux-container VM path. Full real-Docker acceptance on non-Linux runners remains unverified.

## Findings

### 1. Native package-client jobs are feasible on all three OS families

GitHub lists standard Linux, Windows, and macOS hosted runners. Ordinary `run` steps execute on the selected host when a job container is not configured. This supports native local-client and package-manager subprocess tests rather than cross-compilation alone. It establishes **runner capability**, not that this repository's client builds or passes on each OS. [Hosted runners](https://docs.github.com/en/actions/reference/runners/github-hosted-runners), [job execution](https://docs.github.com/en/actions/how-tos/write-workflows/choose-where-workflows-run/run-jobs-in-a-container).

For npm, PyPI, Maven, Go, Cargo, NuGet, CPAN, RubyGems, and Conan, the feasible unit of acceptance is the actual selected package executable plus the local client running as native processes on each target OS. Image inventories contain many relevant runtimes, but do not prove every chosen package client/version is installed or compatible. Pin/setup decisions and native executions are future work. The examined images are representative, not a support matrix for every OS version or architecture. [Ubuntu inventory](https://github.com/actions/runner-images/blob/main/images/ubuntu/Ubuntu2404-Readme.md), [Windows inventory](https://github.com/actions/runner-images/blob/main/images/windows/Windows2025-Readme.md), [macOS inventory](https://github.com/actions/runner-images/blob/main/images/macos/macos-26-arm64-Readme.md).

### 2. A Linux-only server cannot be assumed to run as a service container in Windows/macOS jobs

GitHub explicitly requires a Linux runner for Docker container actions, job containers, and service containers; GitHub-hosted use requires Ubuntu. Services belong to a job, and documented host access uses that job's local port mappings. Consequently, the Linux server can be integrated locally in an Ubuntu job, but `services:` does not provide the same Linux-server arrangement inside native Windows/macOS jobs. [Service containers](https://docs.github.com/en/actions/tutorials/use-containerized-services/use-docker-service-containers).

**Design inference:** Windows/macOS native integration needs an explicitly reachable Linux policy-server endpoint or another independently verified arrangement. A separate Linux job is a separate machine; it is not automatically the Windows/macOS job's localhost. The cited documentation does not establish cross-job endpoint exposure or a network topology. Selecting and proving that connectivity remains future work. Native HTTP/package-client testing and Linux-server integration should be recorded as separate acceptance evidence until that path runs.

### 3. Ubuntu provides the clearest documented real-Docker acceptance environment

The examined Ubuntu 24.04 image lists Docker Client **and Docker Server** 28.0.4, plus Compose/Buildx. Combined with GitHub's Ubuntu container support, this makes an Ubuntu VM a documented candidate for genuine daemon-backed OCI pulls. This does not mean a pull through the local client has passed. [Ubuntu inventory](https://github.com/actions/runner-images/blob/main/images/ubuntu/Ubuntu2404-Readme.md).

Do not generalize this to every Linux label: GitHub's `ubuntu-slim` runner uses an unprivileged container, and Docker-in-Docker is unsupported. Use the runner's documented capability, not just the word Linux. [Hosted runners](https://docs.github.com/en/actions/reference/runners/github-hosted-runners).

### 4. Windows Docker tooling does not prove the required daemon/container mode

The examined Windows Server 2025 image lists Docker 29.7.2, Docker Compose, Docker-wincred and WSL features. It does **not** establish that Docker Desktop is available, that a Linux-container daemon/VM is running, or that this product's intended Linux-image pull path works. A Docker CLI/tool inventory is insufficient evidence for those claims. GitHub's Actions container/service restrictions still apply independently of manually invoking a Docker command. [Windows inventory](https://github.com/actions/runner-images/blob/main/images/windows/Windows2025-Readme.md), [service-container restrictions](https://docs.github.com/en/actions/tutorials/use-containerized-services/use-docker-service-containers).

Result: native Windows client tests are feasible; full real-Docker acceptance for the intended container mode is **unknown**. Windows-container behavior must not be relabeled as Linux-container/Desktop behavior without an explicit scoped test.

### 5. macOS hosted runners do not imply Docker Desktop or nested Linux VM availability

The examined macOS 26 ARM64 inventory does not list Docker tooling/Desktop. GitHub explicitly says nested virtualization is unsupported on ARM64 macOS runners. These facts do not prove that every possible OCI client or remote-daemon test is impossible, but they do prevent assuming an ordinary macOS hosted job includes a usable Docker Desktop/Linux VM setup. Intel macOS Docker feasibility was not established by this bounded review. [macOS inventory](https://github.com/actions/runner-images/blob/main/images/macos/macos-26-arm64-Readme.md), [ARM macOS restrictions](https://docs.github.com/en/actions/reference/runners/github-hosted-runners).

Result: ordinary native macOS package-client tests are feasible; native macOS full real-Docker acceptance is **unknown**. An OCI HTTP fixture test, an installed CLI, or a remote Linux daemon would each prove a narrower property than a local Docker Desktop/VM pull.

## Acceptance boundaries and smallest future proof

| Evidence requested | Feasible documented basis | Remains to prove |
|---|---|---|
| Native local client and ordinary package-client execution on Linux, macOS, Windows | Host `run` steps and standard OS runners | Execute the client and pinned package managers, rather than merely build them. |
| Integration against Linux-only policy server | Ubuntu processes or Linux service container | Native Windows/macOS connectivity to an explicit Linux endpoint; no assumed cross-job localhost. |
| Genuine Docker/OCI pull on Linux | Ubuntu VM Docker Client + Server inventory | Daemon health, actual pull through local client, policy allow/deny, and complete artifact bytes. |
| Genuine Docker/OCI pull on Windows/macOS | No complete intended daemon/VM topology established here | Identify daemon OS/location/container mode and network route; execute the pull before claiming support. |

Smallest future proof: one native job per selected OS executes the built local client and one real package-manager download against a controlled fixture, then demonstrates the Linux policy-server decision over the intended network route. Expand that pattern to the nine ordinary package-client formats. Separately, an Ubuntu VM job records client **and server** Docker versions/health and performs an allowed pull plus a denied pull through the intended local-client route. Add Windows/macOS Docker acceptance only after a usable daemon topology is identified and the same behavior actually runs. These are proposed checks, not commands executed or a selected workflow design.

## Authority, version and method

All six pages are owned by GitHub (`docs.github.com` or `actions/runner-images`) and were fetched 2026-11-02. Documentation method is **documented**; image inventories are **maintainer-documented installed software**, not independently observed running processes.

| Authority | Version/date snapshot | Source identity |
|---|---|---|
| GitHub hosted-runner reference | Current documentation, accessed 2026-11-02 | https://docs.github.com/en/actions/reference/runners/github-hosted-runners |
| GitHub service-container guide | Current documentation, accessed 2026-11-02 | https://docs.github.com/en/actions/tutorials/use-containerized-services/use-docker-service-containers |
| GitHub job-container guide | Current documentation, accessed 2026-11-02 | https://docs.github.com/en/actions/how-tos/write-workflows/choose-where-workflows-run/run-jobs-in-a-container |
| Ubuntu 24.04 image inventory | Image `20261026.354.1`; file blob `97e7ec74186bddefe5bb53c8d3e573955364d89c` | `actions/runner-images/images/ubuntu/Ubuntu2404-Readme.md` |
| Windows Server 2025 image inventory | Image `20261021.299.1`; file blob `84e8dbd2b71809e9315cf0085ce5c3f37c0ffa75` | `actions/runner-images/images/windows/Windows2025-Readme.md` |
| macOS 26 ARM64 image inventory | Image `20261026.0455.2`; file blob `52372b6571987d5a0ce75869ad2ee17c1113e168` | `actions/runner-images/images/macos/macos-26-arm64-Readme.md` |

Conflicts: none. Windows listing Docker and GitHub restricting Actions container features are different claims, not contradictory evidence.

Omitted: other runner images, self-hosted/larger-runner alternatives, exact YAML/actions, remote-daemon architecture selection, and per-package installation instructions.

Limitations: No native runtime pass, Docker pull, network integration, or repository change is demonstrated. Hosted images and `-latest` mappings change; inspect the actual future run's image identity. Non-Linux real-Docker support remains unknown and must not be inferred from native binary tests.
