import string
import unittest
import password_toolkit as pt


class ToolkitTests(unittest.TestCase):
    def test_common_password_is_very_weak(self):
        self.assertEqual(pt.analyze("password")["score"], 0)

    def test_strong_password(self):
        self.assertGreaterEqual(pt.analyze("k9#Vx!2mQz@7Lp4w")["score"], 3)

    def test_sequence_detection(self):
        self.assertTrue(pt.has_sequence("my1234pass"))
        self.assertFalse(pt.has_sequence("k9Vx2mQz"))

    def test_generator_has_all_classes(self):
        pw = pt.generate_password(20)
        self.assertEqual(len(pw), 20)
        self.assertTrue(any(c in string.ascii_lowercase for c in pw))
        self.assertTrue(any(c in string.ascii_uppercase for c in pw))
        self.assertTrue(any(c in string.digits for c in pw))
        self.assertTrue(any(c in pt.SYMBOLS for c in pw))

    def test_generator_rejects_short_length(self):
        with self.assertRaises(ValueError):
            pt.generate_password(4)

    def test_generated_passwords_differ(self):
        self.assertNotEqual(pt.generate_password(), pt.generate_password())


if __name__ == "__main__":
    unittest.main()
