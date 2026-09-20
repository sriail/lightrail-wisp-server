__all__ = [
    "WispConnection",
    "WSProxyConnection",
]


def __getattr__(name):
    if name in __all__:
        from wisp.server.connection import (
            WispConnection,
            WSProxyConnection,
        )

        return {
            "WispConnection": WispConnection,
            "WSProxyConnection": WSProxyConnection,
        }[name]

    raise AttributeError(
        f"module 'wisp.server' has no attribute {name!r}"
    )
