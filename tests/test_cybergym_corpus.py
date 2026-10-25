"""Behavioral regressions for the soundtrace-cybergym-corpus-v1 loader.

Altered digests/platforms/commands/paths, duplicate ids, unknown keys, and
malformed documents must all surface as structured CorpusError values — never
tracebacks — before any image is pulled or any model is called.
"""
import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from soundtrace_live.corpus import (CORPUS_SCHEMA, CorpusError, load_corpus,
                                    parse_corpus, write_corpus)

PILOT = ROOT / 'corpora/cybergym_pilot.json'


def pilot_doc():
    return json.loads(PILOT.read_text())


def write_temp(doc):
    tmp = tempfile.NamedTemporaryFile('w', suffix='.json', delete=False)
    json.dump(doc, tmp)
    tmp.close()
    return Path(tmp.name)


class PilotCorpusTests(unittest.TestCase):
    def test_pinned_pilot_corpus_loads(self):
        corpus = load_corpus(PILOT)
        self.assertEqual(corpus.schema, CORPUS_SCHEMA)
        self.assertEqual(corpus.code_revision,
                         'c6fe2027d39471375920b92cf1025e23a99ffda5')
        self.assertEqual(corpus.platform, 'linux/amd64')
        self.assertEqual(corpus.difficulties, ('level1', 'level0'))
        self.assertEqual(sorted(corpus.tasks),
                         ['arvo:47101', 'arvo:64574', 'oss-fuzz:42535201'])
        arvo = corpus.task('arvo:64574')
        self.assertEqual((arvo.kind, arvo.project, arvo.data_dirname),
                         ('arvo', 'jq', '64574'))
        self.assertEqual(arvo.command_vul, ('/bin/arvo',))
        self.assertEqual(arvo.archive_path, 'data/arvo/64574/repo-vul.tar.gz')
        self.assertEqual(arvo.description_path, 'data/arvo/64574/description.txt')
        self.assertEqual(arvo.poc_mount, '/tmp/poc')
        oss = corpus.task('oss-fuzz:42535201')
        self.assertEqual(oss.command_fix, ('/usr/local/bin/run_poc',))
        self.assertEqual(oss.data_dirname, '42535201')
        self.assertEqual(arvo.vul.digest,
                         'sha256:b73bb925d175e17c85ce73d96792b728c2a20d5763db1f822f443ce398be627d')

    def test_source_hash_is_file_hash(self):
        import hashlib
        corpus = load_corpus(PILOT)
        self.assertEqual(corpus.source_sha256,
                         hashlib.sha256(PILOT.read_bytes()).hexdigest())


class RejectionTests(unittest.TestCase):
    def reject(self, mutate, fragment=None):
        doc = pilot_doc()
        mutate(doc)
        with self.assertRaises(CorpusError) as ctx:
            load_corpus(write_temp(doc))
        self.assertEqual(ctx.exception.reason, 'BAD_INPUT')
        if fragment:
            self.assertIn(fragment, ctx.exception.diagnostic)
        return ctx.exception

    def test_unknown_top_level_key(self):
        self.reject(lambda d: d.update(extra=1), 'corpus keys')

    def test_wrong_schema(self):
        self.reject(lambda d: d.update(schema='other-v0'), 'schema')

    def test_non_amd64_platform(self):
        self.reject(lambda d: d.update(platform='linux/arm64'), 'platform')

    def test_non_amd64_image_platform(self):
        self.reject(lambda d: d['tasks'][0]['images']['vul'].update(platform='linux/arm64'),
                    'platform')

    def test_non_sha256_digest(self):
        def bad(d):
            img = d['tasks'][0]['images']['vul']
            img['digest'] = 'md5:' + '0' * 32
        self.reject(bad, 'digest')

    def test_digest_reference_mismatch(self):
        def bad(d):
            img = d['tasks'][0]['images']['vul']
            img['digest'] = 'sha256:' + 'b' * 64
        self.reject(bad, 'differs from the pinned digest')

    def test_short_digest(self):
        def bad(d):
            img = d['tasks'][0]['images']['fix']
            img['digest'] = img['digest'][:20]
            img['reference'] = img['reference'][: len(img['reference']) - 48]
        self.reject(bad, 'image reference')

    def test_duplicate_task_id(self):
        def dup(d):
            d['tasks'][1]['task_id'] = d['tasks'][0]['task_id']
        self.reject(dup, 'duplicate task id')

    def test_duplicate_difficulty(self):
        self.reject(lambda d: d.update(difficulties=['level1', 'level1']), 'duplicate difficulty')

    def test_wrong_command_for_kind(self):
        def bad(d):
            d['tasks'][2]['command']['vul'] = ['/bin/arvo']
        self.reject(bad, 'command')

    def test_command_with_extra_argv(self):
        def bad(d):
            d['tasks'][0]['command']['fix'] = ['/bin/arvo', '/tmp/poc']
        self.reject(bad, 'command')

    def test_kind_prefix_mismatch(self):
        def bad(d):
            d['tasks'][0]['kind'] = 'oss-fuzz'
        self.reject(bad, 'prefix')

    def test_traversal_archive_path(self):
        def bad(d):
            d['tasks'][0]['sources']['archive'] = 'data/arvo/../arvo/368/repo-vul.tar.gz'
        self.reject(bad, 'archive')

    def test_absolute_description_path(self):
        def bad(d):
            d['tasks'][0]['sources']['description'] = '/etc/passwd'
        self.reject(bad, 'description')

    def test_wrong_task_dirname(self):
        def bad(d):
            d['tasks'][0]['sources']['archive'] = 'data/arvo/369/repo-vul.tar.gz'
        self.reject(bad, 'repo-vul.tar.gz')

    def test_non_heap_class(self):
        self.reject(lambda d: d['tasks'][0].update(vulnerability_class='stack-buffer-overflow'),
                    'heap-buffer-overflow')

    def test_wrong_poc_mount(self):
        self.reject(lambda d: d['tasks'][0].update(poc_mount='/tmp/poc2'), 'poc mount')

    def test_missing_task_field(self):
        def bad(d):
            del d['tasks'][0]['project']
        self.reject(bad, 'task entry keys')

    def test_empty_tasks(self):
        self.reject(lambda d: d.update(tasks=[]), 'nonempty list')

    def test_scope_unfit_task_id_rejected(self):
        # 10-digit oss-fuzz ids pass the shape regex but never fit the
        # 128-char certificate scope cap, even at X1.
        def bad(d):
            d['tasks'][2]['task_id'] = 'oss-fuzz:1234567890'
            d['tasks'][2]['sources']['archive'] = \
                'data/oss-fuzz/1234567890/repo-vul.tar.gz'
            d['tasks'][2]['sources']['description'] = \
                'data/oss-fuzz/1234567890/description.txt'
        self.reject(bad, 'scope cap')

    def test_invalid_task_id_shape(self):
        self.reject(lambda d: d['tasks'][0].update(task_id='arvo:0x11'), 'task id')

    def test_not_json(self):
        tmp = tempfile.NamedTemporaryFile('w', suffix='.json', delete=False)
        tmp.write('{nope')
        tmp.close()
        with self.assertRaises(CorpusError):
            load_corpus(Path(tmp.name))

    def test_unknown_task_lookup(self):
        corpus = load_corpus(PILOT)
        with self.assertRaises(CorpusError) as ctx:
            corpus.task('arvo:999')
        self.assertEqual(ctx.exception.reason, 'UNKNOWN_TASK')

    def test_all_rejections_carry_diagnostics(self):
        for mutate in (
            lambda d: d.update(extra=1),
            lambda d: d['tasks'][0].update(poc_mount='/x'),
            lambda d: d.update(difficulties=[]),
        ):
            doc = pilot_doc()
            mutate(doc)
            with self.assertRaises(CorpusError) as ctx:
                load_corpus(write_temp(doc))
            self.assertTrue(ctx.exception.diagnostic)


class RoundTripTests(unittest.TestCase):
    def test_write_reload_round_trip(self):
        corpus = load_corpus(PILOT)
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / 'regen.json'
            write_corpus(out, corpus)
            again = load_corpus(out)
            self.assertEqual(sorted(again.tasks), sorted(corpus.tasks))
            self.assertEqual(again.task('arvo:64574').vul, corpus.task('arvo:64574').vul)
            self.assertEqual(again.difficulties, corpus.difficulties)

    def test_parse_corpus_rejects_non_object(self):
        for bad in (None, [], 'x', 3):
            with self.assertRaises(CorpusError):
                parse_corpus(bad, source_sha256='0' * 64)

    def test_deep_copy_isolation(self):
        doc = pilot_doc()
        frozen = json.dumps(doc)
        load_corpus(write_temp(doc))
        self.assertEqual(json.dumps(doc), frozen)


if __name__ == '__main__':
    unittest.main()
