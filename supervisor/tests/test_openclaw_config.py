import unittest

from supervisor.openclaw_config import build_gateway_config


class GatewayConfigTests(unittest.TestCase):
    def instance(self, profile='agent_proxy_v1'):
        return {
            'id': 'a' * 32,
            'actor': 'owner_123',
            'network_profile': profile,
            'gateway_token': 'S' * 43,
        }

    def test_legacy_profile_keeps_token_auth_and_loopback_origins(self):
        config = build_gateway_config(self.instance('legacy_none'))
        self.assertEqual(config, {
            'gateway': {
                'mode': 'local',
                'bind': 'lan',
                'auth': {'mode': 'token', 'token': 'S' * 43},
                'controlUi': {'allowedOrigins': [
                    'http://localhost:18789', 'http://127.0.0.1:18789']},
            },
        })

    def test_proxy_profile_trusts_only_exact_sidecar_and_owner(self):
        instance = self.instance()
        instance.update({
            'sidecar_ip': '172.31.4.2',
            'control_ui_origin': 'https://' + 'a' * 32 + '.agents.example.test',
        })
        built = build_gateway_config(instance)
        gateway = built['gateway']
        self.assertEqual(gateway['publicOrigin'], instance['control_ui_origin'])
        self.assertEqual(gateway['trustedProxies'], ['172.31.4.2'])
        self.assertEqual(gateway['controlUi']['allowedOrigins'], [instance['control_ui_origin']])
        self.assertEqual(gateway['auth'], {
            'mode': 'trusted-proxy',
            'identityScopes': {
                'owner_123': ['operator.read', 'operator.write',
                              'operator.approvals', 'operator.questions',
                              'operator.pairing'],
            },
            'trustedProxy': {
                'userHeader': 'x-forwarded-user',
                'requiredHeaders': ['x-forwarded-proto', 'x-forwarded-host'],
                'allowUsers': ['owner_123'],
                'deviceAutoApprove': {'enabled': False},
            },
        })
        self.assertEqual(built['plugins'], {
            'entries': {'admin-http-rpc': {'enabled': True}},
        })
        self.assertNotIn('operator.admin', gateway['auth']['identityScopes']['owner_123'])
        self.assertNotIn('token', gateway['auth'])
        self.assertNotIn('password', gateway['auth'])

    def test_proxy_profile_rejects_missing_or_unsafe_identity_and_origin(self):
        base = self.instance()
        base.update({
            'sidecar_ip': '172.31.4.2',
            'control_ui_origin': 'https://' + 'a' * 32 + '.agents.example.test',
        })
        for changes in (
            {'sidecar_ip': '172.31.4.0/24'},
            {'sidecar_ip': '127.0.0.1'},
            {'sidecar_ip': '172.31.4.2'},
            {'control_ui_origin': 'http://' + 'a' * 32 + '.agents.example.test'},
            {'actor': ''},
            {'id': 'b' * 32},
        ):
            changed = {**base, **changes}
            if changes == {'sidecar_ip': '172.31.4.2'}:
                continue
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                build_gateway_config(changed)

    def test_unknown_profile_fails_closed(self):
        with self.assertRaises(ValueError):
            build_gateway_config(self.instance('legacy_shared'))

    def test_proxy_profile_emits_explicit_native_ollama_models_and_default(self):
        instance = self.instance()
        instance.update({
            'sidecar_ip': '172.31.4.2',
            'control_ui_origin': 'https://' + 'a' * 32 + '.agents.example.test',
        })
        # Synthetic provider policy; values are not deployment defaults.
        ollama = {
            'base_url': 'http://10.99.0.10:11434',
            'default_model_id': 'qwen3.5:9b',
            'context_tokens': 8192,
            'max_tokens': 512,
            'think': False,
        }
        built = build_gateway_config(instance, ollama=ollama)
        provider = built['models']['providers']['ollama']
        self.assertEqual(provider['api'], 'ollama')
        self.assertEqual(provider['baseUrl'], ollama['base_url'])
        models = provider['models']
        self.assertEqual([model['id'] for model in models], ['qwen3.5:9b'])
        self.assertEqual(built['agents']['defaults']['model']['primary'], 'ollama/qwen3.5:9b')
        self.assertEqual(models[0]['contextWindow'], 8192)
        self.assertEqual(models[0]['maxTokens'], 512)
        self.assertEqual(models[0]['params'], {'num_ctx': 8192, 'think': False})

    def test_admin_can_select_each_approved_model_without_exposing_the_other(self):
        instance = self.instance()
        instance.update({
            'sidecar_ip': '172.31.4.2',
            'control_ui_origin': 'https://' + 'a' * 32 + '.agents.example.test',
        })
        approved = (
            'qwen3.5:9b',
            'hf.co/DavidAU/Qwen3.5-9B-The-Defiant-Fable-Uncensored-Heretic-NEO-IMATRIX-MAX-MTP-GGUF:Q4_K_M',
        )
        for model_id in approved:
            policy = {
                'base_url': 'http://10.99.0.10:11434',
                'default_model_id': model_id,
                'context_tokens': 8192,
                'max_tokens': 512,
                'think': False,
            }
            with self.subTest(model_id=model_id):
                built = build_gateway_config(instance, ollama=policy)
                self.assertEqual(
                    [item['id'] for item in built['models']['providers']['ollama']['models']],
                    [model_id],
                )
                self.assertEqual(
                    built['agents']['defaults']['model']['primary'], 'ollama/' + model_id)
                self.assertEqual(
                    built['models']['providers']['ollama']['models'][0]['id'], model_id)


if __name__ == '__main__':
    unittest.main()
