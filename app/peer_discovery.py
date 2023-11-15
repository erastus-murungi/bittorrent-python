from ipaddress import ip_address
from urllib.parse import urlencode, urlparse

import aiohttp
from more_itertools import chunked

from app.bencode import bencode_decode
from app.constants import PEER_ID
from app.torrent import TrackerGetResponse, Torrent, TrackerGetRequestParams, Peer


def _create_tracker_request_params_http(
    torrent: Torrent, first: bool = False, uploaded: int = 0, downloaded: int = 0
) -> TrackerGetRequestParams:
    """
    Creates the request parameters for a GET request to the tracker.

    :param first: True if this is our first request to the tracker
    :param uploaded: The number of bytes uploaded so far
    :param downloaded: The number of bytes downloaded so far
    :return:
    """
    req_params = {
        "info_hash": torrent.info.compute_info_hash().digest(),
        "peer_id": PEER_ID,
        "port": 6881,
        "uploaded": uploaded,
        "downloaded": downloaded,
        "left": torrent.info.get_total_size,
        "compact": 1,
    }
    if first:
        req_params["event"] = "started"
    return req_params


async def discover_peers_http(
    torrent: Torrent, first: bool = False, uploaded: int = 0, downloaded: int = 0
) -> TrackerGetResponse:
    async with aiohttp.ClientSession(trust_env=True) as session:
        async with session.get(
            torrent.announce
            + "?"
            + urlencode(
                _create_tracker_request_params_http(
                    torrent, first, uploaded, downloaded
                )
            )
        ) as tracker_response:
            if tracker_response.status != 200:
                raise ConnectionError(
                    f"Tracker returned status code {tracker_response.status}"
                )
            tracker_content = await tracker_response.read()
            tracker_info = bencode_decode(tracker_content)
            if "failure reason" in tracker_info:
                raise ValueError(
                    f'Failure reason: {tracker_info["failure reason"].decode()}'
                )
            return TrackerGetResponse(
                interval=tracker_info["interval"],
                complete=tracker_info["complete"],
                incomplete=tracker_info["incomplete"],
                peers=[
                    Peer(
                        ip=ip_address(peer_info[: Peer.NUM_BYTES_IN_IP]),
                        port=int.from_bytes(
                            peer_info[Peer.NUM_BYTES_IN_IP :], "big", signed=False
                        ),
                    )
                    for peer_info in map(
                        bytes,
                        chunked(
                            tracker_info["peers"],
                            Peer.NUM_BYTES_IN_PEER,
                            strict=True,  # we want to raise an error if the last chunk is not the right size
                        ),
                    )
                ],
                dict_=tracker_info,
            )


async def discover_peers_udp(
    torrent: Torrent,
    first: bool = False,
    uploaded: int = 0,
    downloaded: int = 0,
) -> TrackerGetResponse:
    pass


async def discover_peers(
    torrent: Torrent, first: bool = False, uploaded: int = 0, downloaded: int = 0
) -> TrackerGetResponse:
    """
    Asynchronously sends a that sends a GET request to the tracker to discover peers.

    :param torrent: The torrent to discover peers for
    :param first: True if this is our first request to the tracker
    :param uploaded: The number of bytes uploaded so far
    :param downloaded: The number of bytes downloaded so far
    :return: TrackerGetResponse
    """

    parsed_url = urlparse(torrent.announce)
    if parsed_url.scheme == "http":
        return await discover_peers_http(torrent, first, uploaded, downloaded)
    elif parsed_url.scheme == "udp":
        return await discover_peers_udp(torrent, first, uploaded, downloaded)
    else:
        raise ValueError(f"Unknown scheme {parsed_url.scheme}")
