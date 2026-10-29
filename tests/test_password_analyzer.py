import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import password_analyzer as pa


class TestCharacters(unittest.TestCase):
    def test_basic(self):
        c = pa.analyze_characters('Abc123!')
        self.assertEqual(c['length'], 7)
        self.assertTrue(c['has_upper'])
        self.assertTrue(c['has_lower'])
        self.assertTrue(c['has_digit'])
        self.assertTrue(c['has_special'])
        self.assertEqual(c['uppercase'], 1)
        self.assertEqual(c['digits'], 3)

    def test_empty(self):
        c = pa.analyze_characters('')
        self.assertEqual(c['length'], 0)
        self.assertFalse(c['has_upper'])


class TestEntropy(unittest.TestCase):
    def test_formula(self):
        h, pool = pa.calculate_entropy('aaaa')
        self.assertEqual(pool, 26)
        self.assertAlmostEqual(h, 4 * __import__('math').log2(26), places=5)

    def test_empty(self):
        h, pool = pa.calculate_entropy('')
        self.assertEqual(h, 0.0)
        self.assertEqual(pool, 0)

    def test_mixed_pool(self):
        _, pool = pa.calculate_entropy('Aa1!')
        self.assertEqual(pool, 26 + 26 + 10 + 32)


class TestPatterns(unittest.TestCase):
    def test_repeated(self):
        self.assertTrue(pa.detect_repeated('aaab'))
        self.assertTrue(pa.detect_repeated('abbb'))
        self.assertFalse(pa.detect_repeated('abcd'))

    def test_sequential(self):
        self.assertTrue(pa.detect_sequential('abc'))
        self.assertTrue(pa.detect_sequential('123'))
        self.assertTrue(pa.detect_sequential('cba'))
        self.assertTrue(pa.detect_sequential('qwerty'))
        self.assertFalse(pa.detect_sequential('azby'))

    def test_substitutions(self):
        self.assertTrue(pa.detect_substitutions('p@ssw0rd'))
        self.assertFalse(pa.detect_substitutions('hello'))

    def test_predictable(self):
        self.assertIn('password', pa.detect_predictable_words('mypassword1'))


class TestCommon(unittest.TestCase):
    def test_loaded(self):
        import tempfile
        fd, path = tempfile.mkstemp()
        os.close(fd)
        with open(path, 'w') as f:
            f.write('secret\npassword\n')
        try:
            matched, status, msg = pa.check_common_password('Password', path)
            self.assertTrue(matched)
            self.assertEqual(status, 'loaded')
            matched2, _, _ = pa.check_common_password('nope', path)
            self.assertFalse(matched2)
        finally:
            os.remove(path)

    def test_missing(self):
        matched, status, msg = pa.check_common_password('x', 'C:/definitely/missing.txt')
        self.assertFalse(matched)
        self.assertEqual(status, 'missing')

    def test_load_wordlist_missing(self):
        self.assertIsNone(pa.load_wordlist('C:/definitely/missing.txt'))


class TestRating(unittest.TestCase):
    def test_common_forces_weak(self):
        zx = pa.zxcvbn_analyze('password')
        patterns = pa.detect_patterns('password')
        entropy, pool = pa.calculate_entropy('password')
        rating = pa.determine_rating('password', zx, True, patterns, entropy)
        self.assertEqual(rating, 'Very Weak')

    def test_empty(self):
        rating = pa.determine_rating('', None, False, pa.detect_patterns(''), 0.0)
        self.assertEqual(rating, 'Very Weak')


class TestAnalyze(unittest.TestCase):
    def test_analyze_returns_keys(self):
        res = pa.analyze('Str0ng!Pass', None)
        self.assertIn('rating', res)
        self.assertIn('entropy', res)
        self.assertIn('reasons', res)
        self.assertIn('recommendations', res)
        self.assertGreater(res['entropy'], 0)


if __name__ == '__main__':
    unittest.main()
