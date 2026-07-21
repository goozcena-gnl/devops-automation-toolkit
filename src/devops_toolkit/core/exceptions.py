"""Toolkit-specific exception hierarchy."""


class ToolkitError(Exception):
    """Base class for controlled toolkit failures."""


class ConfigurationError(ToolkitError):
    """Configuration could not be parsed or validated."""


class DependencyUnavailableError(ToolkitError):
    """A required executable or library is unavailable."""


class CommandExecutionError(ToolkitError):
    """An external command could not be executed safely."""


class SafetyBlockedError(ToolkitError):
    """A safety policy blocked an operation."""
