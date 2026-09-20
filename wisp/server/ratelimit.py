import asyncio
import time


active_clients = {}

enabled = False

connections_limit = 30
bandwidth_limit = 100
window_size = 60


def _window_id():
    return int(time.time() // window_size)


def init_client(client_ip):
    current_window = _window_id()

    client = active_clients.get(client_ip)

    if (
        client is None
        or client.get("window") != current_window
    ):
        active_clients[client_ip] = {
            "window": current_window,
            "streams": 0,
            "tcp": 0,
            "ws": 0,
            "start": time.time(),
        }


def get_client_attr(client_ip, attr):
    init_client(client_ip)
    return active_clients[client_ip][attr]


def set_client_attr(client_ip, attr, value):
    init_client(client_ip)
    active_clients[client_ip][attr] = value


def inc_client_attr(client_ip, attr, amount=1):
    set_client_attr(
        client_ip,
        attr,
        get_client_attr(client_ip, attr) + amount,
    )


def calculate_client_bandwidth(client_ip, attr):
    start_time = get_client_attr(
        client_ip,
        "start",
    )

    total_data = get_client_attr(
        client_ip,
        attr,
    )

    elapsed = max(
        time.time() - start_time,
        0.001,
    )

    return total_data / elapsed / 1000


async def limit_client_bandwidth(
    client_ip,
    length,
    attr,
):
    if not enabled:
        return

    inc_client_attr(
        client_ip,
        attr,
        length,
    )

    while (
        calculate_client_bandwidth(
            client_ip,
            attr,
        )
        > bandwidth_limit
    ):
        await asyncio.sleep(0.01)


def limit_client_bandwidth_sync(
    client_ip,
    length,
    attr,
):
    if not enabled:
        return

    inc_client_attr(
        client_ip,
        attr,
        length,
    )

    while (
        calculate_client_bandwidth(
            client_ip,
            attr,
        )
        > bandwidth_limit
    ):
        time.sleep(0.01)
