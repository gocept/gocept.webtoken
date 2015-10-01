import gocept.webtoken.keys
import pkg_resources
import plone.testing
import plone.testing.zca
import zope.component


class KeysLayer(plone.testing.Layer):
    """Layer setting up utility for providing cryptographic keys."""

    defaultBases = (plone.testing.zca.LAYER_CLEANUP,)

    def __init__(self, keys_dir, names, module=None):
        super(KeysLayer, self).__init__(module=module)
        self.keys_dir = keys_dir
        self.names = names

    def setUp(self):
        self['keys'] = gocept.webtoken.keys.CryptographicKeys(
            self.keys_dir, self.names)
        zope.component.provideUtility(self['keys'])

    def tearDown(self):
        zope.component.getSiteManager().unregisterUtility(self['keys'])
        del self['keys']

KEYS_LAYER = KeysLayer(
    pkg_resources.resource_filename('gocept.webtoken', 'testing/keys'),
    ['jwt-access', 'jwt-application'])
