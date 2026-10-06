"""Exercise the actual bounded runner with harmless owned child processes."""
import subprocess
import sys
import unittest
from unittest.mock import patch

import run_all


class RunnerTests(unittest.TestCase):
    def test_success(self):
        run_all.run('success fixture', ['-c', 'pass'], timeout=10)

    def test_nonzero_exit(self):
        with self.assertRaisesRegex(SystemExit, 'exit status 7'):
            run_all.run('exit fixture', ['-c', 'raise SystemExit(7)'], timeout=10)

    def test_timeout_reaps_own_child(self):
        actual_popen = subprocess.Popen
        children = []

        def capture(*args, **kwargs):
            child = actual_popen(*args, **kwargs)
            children.append(child)
            return child

        with patch.object(run_all.subprocess, 'Popen', side_effect=capture):
            with self.assertRaisesRegex(SystemExit, '0.1-second bound'):
                run_all.run('timeout fixture', ['-c', 'import time; time.sleep(30)'], timeout=0.1)
        self.assertTrue(children)
        self.assertIsNotNone(children[0].poll())

    def test_finished_process_needs_no_signal(self):
        child = subprocess.Popen([sys.executable, '-c', 'pass'])
        self.assertEqual(child.wait(timeout=10), 0)
        run_all.stop_owned_process(child)


if __name__ == '__main__':
    unittest.main()
