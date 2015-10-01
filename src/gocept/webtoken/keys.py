import logging
import gocept.webtoken.interfaces
import os.path
import zope.interface


log = logging.getLogger(__name__)


class CryptographicKeys(object):
    """Provides cryptographic keys for different purposes."""

    zope.interface.implements(gocept.webtoken.interfaces.ICryptographicKeys)

    def __init__(self, keys_dir, names):
        assert os.path.isdir(keys_dir)
        self._keys_dir = keys_dir
        self._store = {}
        for name in names:
            self._read(name, name + '-private')
            self._read(name + '.pub', name + '-public')

    def _read(self, filename, fullname):
        path = os.path.join(self._keys_dir, filename)
        if not os.path.exists(path):
            log.warning('Cryptographic key file %r not found.', path)
            return
        with open(path) as f:
            self._store[fullname] = f.read()

    def __getitem__(self, name):
        return self._store[name]
