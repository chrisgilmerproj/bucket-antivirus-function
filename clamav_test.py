import textwrap
import unittest

from clamav import scan_output_to_json


class TestClamAV(unittest.TestCase):
    def test_scan_output_to_json(self):
        file_path = "/tmp/eicar.com.txt"
        signature = "Eicar-Test-Signature FOUND"
        output = textwrap.dedent(
            """\
        Scanning {0}
        {0}: {1}
        {0}!(0): {1}

        ----------- SCAN SUMMARY -----------
        Known viruses: 6305127
        Engine version: 0.101.4
        Scanned directories: 0
        Scanned files: 1
        Infected files: 1
        Data scanned: 0.00 MB
        Data read: 0.00 MB (ratio 0.00:1)
        Time: 80.299 sec (1 m 20 s)
        """.format(
                file_path, signature
            )
        )
        summary = scan_output_to_json(output)
        self.assertEqual(summary[file_path], signature)
        self.assertEqual(summary["Infected files"], "1")
