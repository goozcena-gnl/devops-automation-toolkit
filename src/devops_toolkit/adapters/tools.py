"""Known CLI adapter definitions."""

from devops_toolkit.adapters.base import ExecutableAdapter

KNOWN_ADAPTERS: dict[str, ExecutableAdapter] = {
    "git": ExecutableAdapter("git", ("--version",)),
    "docker": ExecutableAdapter("docker", ("--version",)),
    "kubectl": ExecutableAdapter("kubectl", ("version", "--client", "--output=json")),
    "terraform": ExecutableAdapter("terraform", ("version", "-json")),
    "tofu": ExecutableAdapter("tofu", ("version", "-json")),
    "helm": ExecutableAdapter("helm", ("version", "--short")),
    "gh": ExecutableAdapter("gh", ("--version",)),
    "az": ExecutableAdapter("az", ("version",)),
    "aws": ExecutableAdapter("aws", ("--version",)),
    "openssl": ExecutableAdapter("openssl", ("version",)),
    "trivy": ExecutableAdapter("trivy", ("--version",)),
    "gitleaks": ExecutableAdapter("gitleaks", ("version",)),
}
