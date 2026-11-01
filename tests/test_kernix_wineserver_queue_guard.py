import importlib.util
import pathlib
import unittest

SCRIPT=pathlib.Path(__file__).resolve().parents[1]/"tools/patch_kernix_wineserver_queue.py"
spec=importlib.util.spec_from_file_location("queueguard",SCRIPT)
m=importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

class WineServerQueueGuardTest(unittest.TestCase):
    def test_null_queue_does_not_read_fd(self):
        patched=m.patch_queue(m.MATCH)
        assert patched.index("if (!queue)")<patched.index("if (queue->fd)")
        self.assertIn("KERNIX_P11_QUEUE_CREATE_FAILED_BEFORE_FD",patched)
        self.assertIn("return;",patched)
        self.assertEqual(m.patch_queue(patched),patched)
    def test_wrong_source_fails_closed(self):
        for bad in ["", "DECL_HANDLER(set_queue_fd){}", m.MATCH+m.MATCH,
                    m.MATCH.replace("queue->fd","queue->sync")]:
            with self.assertRaises(ValueError):m.patch_queue(bad)
    def test_rejected_partial_patch(self):
        with self.assertRaises(ValueError):
            m.patch_queue(m.MATCH+"\n"+m.MARKER)

if __name__=="__main__":unittest.main()
