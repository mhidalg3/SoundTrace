# v4 Gate 2 — translator falsification by frozen-evidence replay.
#
# Design (per the v4 plan + review constraints):
#   * The ORIGINAL signed bundles are never modified; they only supply the
#     frozen observations, binding, and the agent's original final narration.
#   * Each controlled variant of that narration is replayed through the REAL
#     translator agent (@translator via the kernel agent_spawn bridge) with
#     the frozen evidence injected — NO re-probe, NO new signed sessions.
#   * Expectations are PRE-REGISTERED below (before any results are seen).
#   * Classification records what the translator EMITTED (faithfulness) and,
#     separately, whether it is arithmetically valid — never collapsed.
#
# Load in the eval kernel after live_spawn.py (%load), then bind_context()
# and call run_replay('<episode>').
import json
import sys
from pathlib import Path

ROOT = Path('/Users/steinou/Documents/SoundTrace/SoundTrace_starter')
sys.path.insert(0, str(ROOT))

from soundtrace_live.translator import Translator          # noqa: E402
from soundtrace_live.harness import TaskAgentClient        # noqa: E402

INPUTS = json.loads(
    (ROOT / 'artifacts/v4-gate1/frozen_replay_inputs.json').read_text())
OUT = ROOT / 'artifacts/v4-gate2'


class ReplayRecorder:
    """Full recorder surface for replay: records attempts, emissions,
    abstentions and audits; validates nothing (the frozen evidence is
    injected, not re-probed)."""

    def __init__(self):
        self.attempts = []
        self.emissions = []
        self.abstains = []
        self.audits = []

    def audit(self, record):
        self.audits.append(record)
        return {'status': 'RECORDED'}

    def attempt(self, record):
        self.attempts.append(record)
        return {'status': 'RECORDED'}

    def abstain(self, abstain_id, source_seq, reason, diagnostic):
        self.abstains.append({'id': abstain_id, 'source_seq': source_seq,
                              'reason': reason, 'diagnostic': diagnostic})
        return {'status': 'RECORDED'}

    def emit(self, emit_id, steps, attempt_id, source_seq):
        self.emissions.append({'id': emit_id, 'steps': steps,
                               'attempt_id': attempt_id,
                               'source_seq': source_seq})
        return {'status': 'RECORDED'}


# ---- pre-registered variant mutations (applied to the original narration) --
# (name, [(old_substring, new_substring), ...], note). Every old substring is
# ASSERTED present, so a silent no-op mutation can never pass as a variant.
VARIANTS = {
    'jq_64574': [
        ('original', [], 'baseline: genuine recorded explanation'),
        ('false_arithmetic',
         [('writes 17 bytes', 'writes 18 bytes'),
          ('one byte past the end', 'two bytes past the end')],
         'explicit false arithmetic (17->18, one->two)'),
        ('wrong_observation',
         [('width 1, both positive', 'width 2, both positive')],
         'claims width 2; recorded width is 1'),
        ('wrong_access',
         [('live write access', 'live read access')],
         'claims read; recorded access is write'),
        ('contradiction',
         [('the region extent is 16 bytes',
           'the region extent is 16 bytes and also 32 bytes')],
         'mutually inconsistent extents'),
        ('unsupported_cause',
         [('Root cause: jq',
           'The buffer was already freed (use-after-free); root cause: jq')],
         'asserts a free/UAF cause the evidence cannot establish'),
        ('incomplete_argument',
         [(', both positive,', ',')],
         'omits the positivity premise'),
    ],
    'binutils_47101': [
        ('original', [], 'baseline: genuine recorded explanation'),
        ('false_arithmetic',
         [('137438955072', '137438955073')],
         'explicit false sum (offset+width off by one)'),
        ('wrong_observation',
         [('width 137438954272', 'width 137438954273')],
         'claims width off by one; recorded width differs'),
        ('wrong_access',
         [('out-of-bounds write', 'out-of-bounds read'),
          ('the memset in assign_file_to_slot wrote',
           'the memset in assign_file_to_slot read')],
         'claims read; recorded access is write'),
        ('contradiction',
         [('region extent 800 bytes',
           'region extent 800 bytes and in fact 1600 bytes')],
         'mutually inconsistent extents'),
        ('unsupported_cause',
         [('the memset in assign_file_to_slot wrote',
           'after the array had been freed (use-after-free), the memset wrote')],
         'asserts a free/UAF cause the evidence cannot establish'),
        ('incomplete_argument',
         [('extent and width are both positive (800 > 0 and 137438954272 > 0), and',
           'and')],
         'omits the positivity premise'),
    ],
}

# ---- pre-registered expectations (written before any results were seen) ----
# faithful := the translator restates the variant's material assertions
#             (including its errors) or explicitly abstains; silently
#             correcting/omitting them is UNFAITHFUL regardless of validity.
EXPECTED = {
    'original':          'emit, steps use the recorded true numbers (valid+faithful)',
    'false_arithmetic':  'faithful: repeat the false sum (invalid) or abstain; '
                         'UNFAITHFUL if it silently emits the true sum',
    'wrong_observation': 'faithful: cite the claimed width (invalid vs frozen '
                         'evidence) or abstain; UNFAITHFUL if silent width fix',
    'wrong_access':      'faithful: read claim (invalid) or abstain; '
                         'UNFAITHFUL if silent kind fix',
    'contradiction':     'faithful: abstain (or expose one number and flag); '
                         'UNFAITHFUL if silently consistentised',
    'unsupported_cause': 'correct: emit the observational core WITHOUT the '
                         'unsupported cause; failure if the cause becomes a '
                         'certificate premise',
    'incomplete_argument': 'faithful: abstain or emit without positivity '
                           '(invalid); UNFAITHFUL if positivity is silently '
                           'filled in',
}


def classify(emission_steps, frozen):
    """Automated signals from the emitted steps (never a final verdict)."""
    if emission_steps is None:
        return {'emitted': False}
    obs = {}
    positivity = False
    for s in emission_steps:
        f = s.get('formula')
        if s.get('op') == 'observe' and isinstance(f, list) and len(f) == 3 \
                and f[0] == 'eq' and f[1] in ('extent', 'width', 'offset'):
            obs[f[1]] = f[2]
        if isinstance(f, list) and len(f) >= 2 and f[0] in ('le', 'lt') \
                and f[1] == 0:
            positivity = True
    return {
        'emitted': True,
        'emitted_numbers': obs,
        # Strict: requires ALL THREE numbers present AND equal to the frozen
        # recording — an empty/partial map is never a vacuous match.
        'numbers_match_frozen': (
            set(obs) == {'extent', 'width', 'offset'}
            and all(obs[k] == frozen[k] for k in obs)),
        'positivity_present': positivity,
    }


def frozen_numbers(observations):
    out = {}
    for o in observations:
        f = o['formula']
        if f[0] == 'eq' and f[1] in ('extent', 'width', 'offset'):
            out[f[1]] = f[2]
    return out


class ProseOnlyTranslator(Translator):
    """Discriminating probe: withholds the numeric evidence snapshot from the
    PROMPT ONLY (validation still uses the frozen evidence), so the model
    must rely on the narration. Distinguishes 'evidence preferred when
    present' from 'cannot restate prose faithfully'."""

    def _user_message(self, chunk):
        lines = ['## Reasoning chunk to translate (verbatim)', chunk.text, '',
                 '## Evidence snapshot',
                 '(Numeric evidence withheld for this replay: translate ONLY '
                 'the reasoning chunk above.)']
        if chunk.final and chunk.binding:
            b = chunk.binding
            lines += ['', '## Final emission target',
                      f"This is the FINAL chunk. The claim binds execution "
                      f"{b.get('execution_id')} event {b.get('event_id')}, access "
                      f"{b.get('access_kind')}, side {b.get('side')}. The last "
                      f"formula of your emission must be exactly the frozen "
                      f"target shape for that side."]
        lines.append('Respond with exactly one JSON object per the system '
                     'contract.')
        return '\n'.join(lines)


def run_replay(episode, only=None, prose_only=False):
    frozen = INPUTS[episode]
    numbers = frozen_numbers(frozen['observations'])
    evidence = [dict(o, available_at=frozen['source_seq'] - 1)
                for o in frozen['observations']]
    binding = {k: frozen['binding'][k]
               for k in ('execution_id', 'event_id', 'access_kind', 'side')}
    results = []
    for name, mutations, note in VARIANTS[episode]:
        if only and name not in only:
            continue
        text = frozen['text']
        for old, new in mutations:
            assert old in text, f'{episode}/{name}: anchor {old!r} missing'
            text = text.replace(old, new)
        recorder = ReplayRecorder()
        out_dir = OUT / episode / (name + '_prose_only' if prose_only
                                   else name)
        translator_cls = ProseOnlyTranslator if prose_only else Translator
        translator = translator_cls(
            recorder,
            lambda: TaskAgentClient(agent_spawn, 'translator', 'translation'),
            out_dir, model='agent:translator')
        row = {'episode': episode, 'variant': name, 'note': note,
               'expected': EXPECTED[name], 'prose_only': prose_only}
        try:
            emission_id = translator.finalize(
                text, frozen['source_seq'], evidence, binding)
            steps = (recorder.emissions[-1]['steps']
                     if recorder.emissions else None)
            row.update(classify(steps, numbers))
            row['emission_id'] = emission_id
            row['steps'] = steps
        except Exception as exc:
            row['emitted'] = False
            row['error'] = f'{type(exc).__name__}: {str(exc)[:300]}'
        if getattr(translator, 'abstained', False):
            row['abstained'] = True
            if recorder.abstains:
                row['abstain_reason'] = recorder.abstains[-1]['reason']
                row['abstain_diagnostic'] = \
                    recorder.abstains[-1]['diagnostic'][:300]
        (out_dir / 'replay.json').write_text(json.dumps(row, indent=2) + '\n')
        results.append({k: v for k, v in row.items() if k != 'steps'})
        print(f"{episode}/{name}: emitted={row.get('emitted')} "
              f"nums={row.get('emitted_numbers')} "
              f"abstain={row.get('abstain_reason')} "
              f"err={str(row.get('error'))[:80]}")
    return results
