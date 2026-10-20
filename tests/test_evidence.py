"""Behavioral regressions for strict evidence loading and canonicalization."""
import tempfile
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from evidence import LIMIT_BYTES, Rejected, canonical_json, load_json, mac_hex, mac_matches, parse_json


class ParseJsonTests(unittest.TestCase):
    def test_duplicate_object_keys_rejected(self):
        with self.assertRaises(Rejected):
            parse_json('{"records": {"E1": {"available_at": 1}}, '
                       '"records": {"E1": {"available_at": 99}}}')

    def test_duplicate_nested_keys_rejected(self):
        with self.assertRaises(Rejected):
            parse_json('{"a": 1, "b": {"x": 1, "x": 2}}')

    def test_nonfinite_constants_rejected(self):
        for text in ('{"a": NaN}', '{"a": Infinity}', '{"a": -Infinity}'):
            with self.assertRaises(Rejected):
                parse_json(text)

    def test_nonfinite_float_literal_rejected(self):
        with self.assertRaises(Rejected):
            parse_json('{"a": 1e999}')

    def test_malformed_json_rejected_not_crash(self):
        for text in ('', '{', '[1,', 'null }', '"unterminated', '{]}'):
            with self.assertRaises(Rejected):
                parse_json(text)

    def test_deep_nesting_rejected_not_recursion_error(self):
        with self.assertRaises(Rejected):
            parse_json('[' * 100000 + ']' * 100000)

    def test_non_string_input_rejected(self):
        with self.assertRaises(Rejected):
            parse_json(b'{"a": 1}')

    def test_valid_document_round_trips(self):
        self.assertEqual(parse_json('{"b": 1, "a": [1, 2, 3]}'),
                         {'a': [1, 2, 3], 'b': 1})


class CanonicalJsonTests(unittest.TestCase):
    def test_key_order_is_irrelevant_to_bytes(self):
        a = canonical_json({'x': 1, 'y': {'b': 2, 'a': 3}})
        b = canonical_json({'y': {'a': 3, 'b': 2}, 'x': 1})
        self.assertEqual(a, b)

    def test_compact_separators_and_no_trailing_newline(self):
        data = canonical_json({'a': [1, 2], 'b': 'x'})
        self.assertEqual(data, b'{"a":[1,2],"b":"x"}')
        self.assertFalse(data.endswith(b'\n'))

    def test_non_ascii_escaped(self):
        self.assertEqual(canonical_json({'k': 'é'}), b'{"k":"\\u00e9"}')

    def test_nonfinite_value_rejected(self):
        with self.assertRaises(Rejected):
            canonical_json({'a': float('nan')})

class LoadJsonTests(unittest.TestCase):
    def test_loads_strict_object(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'ok.json'
            path.write_text('{"a": 1}')
            self.assertEqual(load_json(path), {'a': 1})

    def test_duplicate_keys_rejected_on_load(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'dup.json'
            path.write_text('{"a": 1, "a": 2}')
            with self.assertRaises(Rejected):
                load_json(path)

    def test_size_limit_enforced(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'big.json'
            path.write_text(' ' * (LIMIT_BYTES + 1))
            with self.assertRaises(Rejected):
                load_json(path)

    def test_non_object_top_level_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'arr.json'
            path.write_text('[1, 2]')
            with self.assertRaises(Rejected):
                load_json(path)

    def test_missing_file_rejected(self):
        with self.assertRaises(Rejected):
            load_json(Path('/nonexistent/definitely/missing.json'))

class MacTests(unittest.TestCase):
    def test_mac_is_deterministic_and_keyed(self):
        self.assertEqual(mac_hex(b'k', b'p'), mac_hex(b'k', b'p'))
        self.assertNotEqual(mac_hex(b'k', b'p'), mac_hex(b'k2', b'p'))

    def test_mac_matches(self):
        tag = mac_hex(b'k', b'p')
        self.assertTrue(mac_matches(b'k', b'p', tag))
        self.assertFalse(mac_matches(b'k', b'p2', tag))
        self.assertFalse(mac_matches(b'k', b'p', tag.upper()))
        self.assertFalse(mac_matches(b'k', b'p', None))


if __name__ == '__main__':
    unittest.main()
