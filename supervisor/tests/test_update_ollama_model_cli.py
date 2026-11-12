import unittest

from scripts.update_ollama_model import build_payload


class UpdateOllamaModelCliTests(unittest.TestCase):
    def test_status_payload_is_read_only_and_exact(self):
        self.assertEqual(build_payload('status'), {'action': 'status'})

    def test_set_payload_uses_explicit_compare_and_swap_model_ids(self):
        old = 'qwen3.5:9b'
        new = 'hf.co/DavidAU/Qwen3.5-9B-The-Defiant-Fable-Uncensored-Heretic-NEO-IMATRIX-MAX-MTP-GGUF:Q4_K_M'
        self.assertEqual(build_payload('set', old, new), {
            'expected_model_id': old, 'new_model_id': new,
        })

    def test_set_payload_rejects_unapproved_model_ids(self):
        with self.assertRaises(ValueError):
            build_payload('set', 'qwen3.5:9b', 'unapproved:model')


if __name__ == '__main__':
    unittest.main()
