"""Producer/checker input parity on small authored finite programs."""
import unittest

from checker.independent_checker import CheckFailure, _validate_program, check_certificate
from pathseal.model import ModelError, validate_program
from pathseal.producer import produce_certificate
from test_contract import program


class ProgramSchemaTests(unittest.TestCase):
    def rejected_by_both(self, subject):
        with self.assertRaises(ModelError):
            validate_program(subject)
        with self.assertRaises(ModelError):
            produce_certificate(subject)
        with self.assertRaises(CheckFailure):
            _validate_program(subject)

    def test_closed_program_handoff(self):
        subject = program()
        validate_program(subject)
        _validate_program(subject)
        self.assertEqual(check_certificate(produce_certificate(subject))['status'], 'PASS')

    def test_extra_program_metadata_is_rejected_by_both(self):
        subject = program()
        subject['metadata'] = {'label': 'owned finite fixture'}
        self.rejected_by_both(subject)

    def test_extra_segment_metadata_is_rejected_by_both(self):
        subject = program()
        subject['segments'][0]['metadata'] = 'owned finite fixture'
        self.rejected_by_both(subject)

    def test_program_name_must_be_a_nonempty_string(self):
        for name in ['', None, 1]:
            with self.subTest(name=name):
                subject = program()
                subject['name'] = name
                self.rejected_by_both(subject)

    def test_event_name_must_be_a_nonempty_string(self):
        for name in ['', None, 1]:
            with self.subTest(name=name):
                subject = program([{'op': 'emit', 'event': name, 'args': []}])
                self.rejected_by_both(subject)


if __name__ == '__main__':
    unittest.main()
