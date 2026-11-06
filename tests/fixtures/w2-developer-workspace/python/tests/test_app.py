import unittest

from src.app import greeting


class GreetingTests(unittest.TestCase):
    def test_greeting_is_editable_and_testable(self) -> None:
        self.assertEqual(greeting(), "Tinlance Agent Workspace")


if __name__ == "__main__":
    unittest.main()
