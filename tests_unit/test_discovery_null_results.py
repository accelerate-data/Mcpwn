"""Discovery tolerates a malformed tools/list or resources/list result."""

import pytest

from core.pentester import MCPPentester

INITIALIZE = {"jsonrpc": "2.0", "id": 1, "result": {"protocolVersion": "2024-11-05"}}


class _FakeTransport:
    """Return canned JSON-RPC responses without a running server."""

    def __init__(self, responses):
        self._responses = responses

    def start(self):
        pass

    def stop(self):
        pass

    def is_alive(self):
        return True

    def send_request(self, method, params=None, timeout=None):
        return self._responses[method], 0.0


def _pentester(responses):
    pentester = MCPPentester(
        "http://127.0.0.1:1/", {"timeout": 1}, transport_type="http"
    )
    pentester.transport = _FakeTransport(responses)
    return pentester


def _responses(tools_result, resources_result):
    return {
        "initialize": INITIALIZE,
        "tools/list": {"jsonrpc": "2.0", "id": 2, "result": tools_result},
        "resources/list": {"jsonrpc": "2.0", "id": 3, "result": resources_result},
    }


def test_null_resources_are_normalized_to_empty_list():
    the_pentester = _pentester(
        _responses(
            {"tools": [{"name": "extract"}]},
            {"ttlMs": 0, "cacheScope": "public", "resources": None},
        )
    )

    tools, resources = the_pentester.discover()

    assert tools == [{"name": "extract"}]
    assert resources == []
    assert len(tools) == 1
    assert len(resources) == 0


def test_null_tools_are_normalized_to_empty_list():
    the_pentester = _pentester(
        _responses(
            {"tools": None},
            {"resources": [{"uri": "file:///a"}]},
        )
    )

    tools, resources = the_pentester.discover()

    assert tools == []
    assert resources == [{"uri": "file:///a"}]


def test_absent_fields_still_default_to_empty_lists():
    the_pentester = _pentester(_responses({}, {}))

    tools, resources = the_pentester.discover()

    assert tools == []
    assert resources == []


@pytest.mark.parametrize("bad_result", [None, [], "not-a-dict", 5])
def test_non_object_result_is_treated_as_empty(bad_result):
    the_pentester = _pentester(_responses(bad_result, bad_result))

    tools, resources = the_pentester.discover()

    assert tools == []
    assert resources == []
