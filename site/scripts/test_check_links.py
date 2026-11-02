"""Compatibility anchors remain linkable after a documentation heading rename."""
import pathlib
import tempfile
import unittest

from check_links import check, slugs


class AnchorTest(unittest.TestCase):
    def test_renamed_heading_and_legacy_anchor(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            target = root / 'proposal.md'
            target.write_text('<a id="llm-api-fallback"></a>\n\n### Model API fallback\n')
            source = root / 'index.md'
            source.write_text('[Old](proposal.md#llm-api-fallback)\n'
                              '[New](proposal.md#model-api-fallback)\n')
            self.assertEqual(slugs(target), {'llm-api-fallback', 'model-api-fallback'})
            self.assertEqual(check(directory, source, 'index.md'), ([], 2, 0))

    def test_examples_do_not_define_anchors(self):
        with tempfile.TemporaryDirectory() as directory:
            target = pathlib.Path(directory) / 'example.md'
            target.write_text('```html\n<a id="fenced"></a>\n```\n'
                              '`<a id="inline"></a>`\n'
                              '<a id="actual"></a>\n')
            self.assertEqual(slugs(target), {'actual'})


if __name__ == '__main__':
    unittest.main()
