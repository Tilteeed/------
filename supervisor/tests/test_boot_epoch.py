"""Real SQLite evidence that Supervisor restart is not another host reboot."""
from pathlib import Path
import tempfile
import unittest
from supervisor.runtime_store import RuntimeStore, StoreError


class BootEpochTests(unittest.TestCase):
    def test_baseline_then_one_claim_per_new_linux_boot_persists(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'runtime.sqlite'
            first='11111111-1111-4111-8111-111111111111'
            second='22222222-2222-4222-8222-222222222222'
            store=RuntimeStore(path,'1','synthetic')
            try:
                self.assertFalse(store.claim_boot_recovery(first), 'First observation only establishes a baseline')
                self.assertFalse(store.claim_boot_recovery(first))
            finally: store.close()
            store=RuntimeStore(path,'1','synthetic')
            try:
                self.assertFalse(store.claim_boot_recovery(first), 'Service restart must not restart crashed workloads')
                self.assertTrue(store.claim_boot_recovery(second))
                self.assertFalse(store.claim_boot_recovery(second), 'Claim is consumed before Docker mutations')
                for malformed in ('',None,True,'short','A'*36,second+'\n'):
                    with self.subTest(value=malformed):
                        with self.assertRaises(StoreError): store.claim_boot_recovery(malformed)
            finally: store.close()
            store=RuntimeStore(path,'1','synthetic')
            try: self.assertFalse(store.claim_boot_recovery(second))
            finally: store.close()

if __name__=='__main__': unittest.main()
