"""Path-traversal canary scoping: the out-of-root canary must be planted OUTSIDE the server's
allowed root, so a broadly-scoped server (root=/tmp, $HOME, /) can't false-positive."""
from hunt.probes import _outside_root_dir, _under


def test_under_has_proper_boundary():
    assert _under("/tmp/x/y", "/tmp") is True
    assert _under("/tmp", "/tmp") is True
    assert _under("/var/tmp", "/tmp") is False
    assert _under("/tmproot/x", "/tmp") is False      # prefix trap — NOT inside /tmp


def test_outside_root_dir_picks_a_dir_outside_the_root():
    d = _outside_root_dir(["/tmp"])
    assert d is not None and not _under(str(d), "/tmp")   # e.g. /var/tmp or /dev/shm or $HOME
    import shutil
    shutil.rmtree(d, ignore_errors=True)


def test_outside_root_dir_none_when_root_spans_everything():
    # root '/' covers every candidate base -> no out-of-root location -> traversal not testable
    assert _outside_root_dir(["/"]) is None
