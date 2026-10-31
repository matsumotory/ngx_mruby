"""Contract tests for conservative runtime-CI selection (no nginx required)."""
import importlib.util
import pathlib
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('change_scope', ROOT / 'test/ci/change_scope.py')
scope = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scope)


class ScopeTests(unittest.TestCase):
    def test_known_non_runtime_inputs(self):
        for path, category in [('AGENTS.md', 'records'), ('docs/HANDOFF.md', 'records'),
                               ('docs/install/README.md', 'content'),
                               ('site/src/content/docs/index.mdx', 'site-content'),
                               ('site/src/styles/main.css', 'site'),
                               ('site/package-lock.json', 'site'),
                               ('examples/start/README.md', 'examples'),
                               ('examples/start/route.rb', 'examples')]:
            with self.subTest(path=path):
                result = scope.classify([(path, '100644', '100644')])
                self.assertFalse(result['runtime'])
                self.assertIn(category, result['categories'])

    def test_unknown_and_shared_inputs_always_full(self):
        for path in ['src/http/module.c', 'mrbgems/foo.rb', 'mruby/README.md',
                     'dependence/README.md', 'build.sh', 'build_config.rb.lock',
                     'configure.in', 'nginx_version', 'test/t/test.rb',
                     '.github/workflows/site.yml', '.github/workflows/test.yml',
                     'Dockerfile', '.gitmodules', 'new-helper.py',
                     'docs/new-helper.sh', 'example/nginx.conf', 'misc/README.md']:
            with self.subTest(path=path):
                self.assertTrue(scope.classify([(path, '100644', '100644')])['runtime'])

    def test_mixed_and_mode_changes_fail_closed(self):
        self.assertTrue(scope.classify([('docs/README.md', '100644', '100644'),
                                        ('src/a.c', '100644', '100644')])['runtime'])
        for before, after in [('100644', '120000'), ('160000', '000000'),
                              ('100644', '100755')]:
            self.assertTrue(scope.classify([('site/a', before, after)])['runtime'])
        for path in ['', '/site/a', '../site/a', 'site/../build.sh', 'site/a\nb']:
            self.assertTrue(scope.classify([(path, '100644', '100644')])['runtime'])
        self.assertTrue(scope.classify([])['runtime'])

    def test_add_and_delete_regular_content(self):
        for before, after in [('000000', '100644'), ('100644', '000000')]:
            self.assertFalse(scope.classify([('docs/a.md', before, after)])['runtime'])

    def test_gate_is_strict(self):
        for runtime, build, soak in [('true', 'success', 'success'),
                                     ('false', 'skipped', 'skipped')]:
            self.assertTrue(scope.gate('success', runtime, build, soak, 'success'))
        for result in ['failure', 'cancelled', 'skipped', '']:
            self.assertFalse(scope.gate(result, 'false', 'skipped', 'skipped', 'success'))
            self.assertFalse(scope.gate('success', 'false', 'skipped', 'skipped', result))
        for runtime in ['', 'FALSE', 'unknown']:
            self.assertFalse(scope.gate('success', runtime, 'skipped', 'skipped', 'success'))
        for result in ['failure', 'cancelled', 'skipped']:
            self.assertFalse(scope.gate('success', 'true', result, 'success', 'success'))
        self.assertFalse(scope.gate('success', 'false', 'failure', 'skipped', 'success'))

    def test_git_rename_checks_both_paths_and_deletions(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            def git(*args):
                return subprocess.check_output(['git', '-C', directory, *args], text=True).strip()
            git('init', '-q'); git('config', 'user.email', 'test@example.invalid')
            git('config', 'user.name', 'Test')
            (root / 'runtime.c').write_text('original runtime\n')
            git('add', '.'); git('commit', '-qm', 'base')
            base = git('rev-parse', 'HEAD')
            (root / 'site').mkdir()
            git('mv', 'runtime.c', 'site/runtime.c')
            git('commit', '-qm', 'move')
            changes = scope.changed_files(base, 'HEAD', cwd=directory)
            self.assertEqual({c[0] for c in changes}, {'runtime.c', 'site/runtime.c'})
            self.assertTrue(scope.classify(changes)['runtime'])

    def test_non_range_events_are_full(self):
        for env in [{}, {'EVENT_NAME': 'workflow_dispatch'},
                    {'EVENT_NAME': 'schedule'},
                    {'EVENT_NAME': 'push', 'REF_TYPE': 'tag'},
                    {'EVENT_NAME': 'push', 'REF_TYPE': 'branch', 'PUSH_BEFORE': '0' * 40},
                    {'EVENT_NAME': 'push', 'REF_TYPE': 'branch', 'PUSH_BEFORE': 'bad'}]:
            self.assertTrue(scope.event_scope(env)['runtime'])

    def test_pr_uses_merge_parent_not_old_branch_fork(self):
        with patch.object(scope.subprocess, 'check_call') as verify, \
                patch.object(scope, 'changed_files', return_value=[('docs/a.md', '100644', '100644')]) as diff:
            self.assertFalse(scope.event_scope({'EVENT_NAME': 'pull_request'})['runtime'])
            verify.assert_called_once()
            diff.assert_called_once_with('HEAD^1', 'HEAD')

    def test_branch_push_uses_both_endpoints(self):
        env = {'EVENT_NAME': 'push', 'REF_TYPE': 'branch',
               'PUSH_BEFORE': 'a' * 40, 'PUSH_SHA': 'b' * 40}
        with patch.object(scope.subprocess, 'call', return_value=0), \
                patch.object(scope, 'changed_files', return_value=[('docs/a.md', '100644', '100644')]) as diff:
            self.assertFalse(scope.event_scope(env)['runtime'])
            diff.assert_called_once_with('a' * 40, 'b' * 40)
        with patch.object(scope.subprocess, 'call', return_value=1), \
                patch.object(scope.subprocess, 'check_call', side_effect=subprocess.CalledProcessError(1, 'fetch')):
            with self.assertRaises(subprocess.CalledProcessError):
                scope.event_scope(env)

    def test_cli_falls_back_to_full_and_outputs_decision(self):
        with tempfile.TemporaryDirectory() as directory:
            output = pathlib.Path(directory) / 'outputs'
            summary = pathlib.Path(directory) / 'summary'
            env = {'GITHUB_OUTPUT': str(output), 'GITHUB_STEP_SUMMARY': str(summary)}
            with patch.dict(scope.os.environ, env, clear=True), \
                    patch.object(scope, 'event_scope', side_effect=ValueError('bad diff')), \
                    patch('sys.argv', ['change_scope.py']):
                self.assertEqual(scope.main(), 0)
            self.assertEqual(output.read_text(), 'runtime=true\n')
            self.assertIn('classification-fallback', summary.read_text())

    def test_workflow_keeps_gate_and_full_matrix(self):
        text = (ROOT / '.github/workflows/test.yml').read_text()
        self.assertIn('needs: [scope, build, soak, files]', text)
        self.assertIn('if: always()', text.split('  ci-ok:', 1)[1])
        for job in ('build', 'soak'):
            body = text.split('  ' + job + ':\n', 1)[1].split('    runs-on:', 1)[0]
            self.assertIn('needs: scope', body)
            self.assertIn("needs.scope.outputs.runtime == 'true'", body)
        for version in ('1.31.8', '1.30.6', '1.28.3', '1.26.3'):
            self.assertIn('- ' + version, text)
        self.assertIn('SANITIZER:', text)
        self.assertNotIn('paths-ignore:', text)

    def test_unavailable_base_cannot_be_treated_as_empty_diff(self):
        with self.assertRaises(subprocess.CalledProcessError):
            scope.changed_files('not-a-real-revision', 'HEAD', cwd=ROOT)


if __name__ == '__main__':
    unittest.main()
