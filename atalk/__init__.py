"""ATalk: a small reliable message bus for AI agents."""

try:  # installed as a package
    from importlib.metadata import version as _v, PackageNotFoundError
    try:
        __version__ = _v("atalk")
    except PackageNotFoundError:  # running from a source checkout
        __version__ = "0.3.0a2"
except Exception:  # pragma: no cover
    __version__ = "0.3.0a2"
