"""Opt-in kernel regression; all nft mutations stay in a new network namespace."""
import os
import subprocess
import sys
import unittest


@unittest.skipUnless(sys.platform == 'linux' and os.environ.get('BEZR_RUN_NFT_INTEGRATION') == '1',
                     'requires explicitly enabled Linux root network namespace')
class NftKernelIntegrationTests(unittest.TestCase):
    def test_arp_dependency_is_present_with_or_without_explicit_ether_type(self):
        # The nftables netlink debug output is the compiled kernel instruction
        # stream, not JSON's potentially abbreviated display of the rule.
        code = r'''
import subprocess
def nft(*args):
    return subprocess.run(('nft', *args), check=True, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, text=True, timeout=10).stdout
nft('add', 'table', 'bridge', 'bezr_probe')
nft('add', 'chain', 'bridge', 'bezr_probe', 'input')
tail = ('arp', 'saddr', 'ip', '10.98.0.2', 'arp', 'daddr', 'ip', '10.98.0.1',
        'arp', 'operation', 'request', 'accept')
prefix = ('-d', 'netlink', 'add', 'rule', 'bridge', 'bezr_probe', 'input')
explicit = nft(*prefix, 'ether', 'type', 'arp', *tail)
implicit = nft(*prefix, *tail)
if explicit != implicit or 'link header + 12' not in implicit:
    raise SystemExit('ARP protocol dependency differs')
'''
        subprocess.run(('unshare', '--net', '--', sys.executable, '-c', code), check=True,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)


if __name__ == '__main__':
    unittest.main()
