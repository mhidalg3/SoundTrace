# Kernel-side agent_spawn bridge for the SoundTrace pipeline.
# %load in the eval kernel, call start_pump() IN THE LAUNCH CELL (so the pump
# task carries that cell's live python tool-bridge session), then pass
# spawn=agent_spawn to run_campaign / run_on_harness_agents.
#
# Why a pump: orchestrator bridge calls arrive on foreign threads (the
# asyncio.to_thread worker and — for the translator — a raw TranslatorWorker
# thread with an empty context). Scheduling kernel agent()/tool() calls from
# those contexts via copied Contexts deadlocks or drops the session binding.
# Instead, raw threads only enqueue through loop.call_soon_threadsafe; a pump
# task created in the live cell executes every spawn start-to-finish in the
# cell's own context.
#
# Tool contracts mirror the installed agent definitions exactly:
#   pilot      (agents/pilot.md):      submit_action(tool, arguments, reasoning_chunk)
#   translator (agents/translator.md): submit_translation(response_object)
import asyncio
import contextvars
import sys
from pathlib import Path

ROOT = Path('/Users/steinou/Documents/SoundTrace/SoundTrace_starter')
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

try:
    _loop = asyncio.get_running_loop()
except RuntimeError:
    _loop = asyncio.get_event_loop()

_capture_ctx = None


async def _do_spawn(agent_name, prompt):
    box = {}
    if agent_name == 'translator':
        def submit_translation(response: dict, **extra) -> str:
            if extra:
                keys = ', '.join(sorted(extra))
                return ('ERROR: submit_translation takes exactly one response '
                        f'object. Extra parameter(s) {keys} are not accepted. '
                        'Nothing was recorded; call again corrected.')
            box['p'] = dict(response)
            return 'RECORDED — reply with exactly DONE.'
        fn, tname = submit_translation, 'submit_translation'
    else:
        def submit_action(tool: str, arguments: dict, reasoning_chunk: str,
                          **extra) -> str:
            if extra:
                # Never silently drop misplaced fields: a report_oob that put
                # `side` here would fail validation without a fixable cause.
                keys = ', '.join(sorted(extra))
                return ('ERROR: submit_action takes exactly (tool, arguments, '
                        'reasoning_chunk). Extra parameter(s) '
                        f'{keys} must go INSIDE the arguments object. '
                        'Nothing was recorded; call again corrected.')
            box['p'] = {'tool': tool, 'arguments': arguments,
                        'reasoning_chunk': reasoning_chunk}
            return 'RECORDED — reply with exactly DONE.'
        fn, tname = submit_action, 'submit_action'
    tool(fn, name=tname)
    handle = None
    try:
        handle = agent(prompt, agent=agent_name, tools=[tname],
                       label=f'cg-{tname}-{id(box):x}')
        for _ in range(840):          # poll until the agent calls its tool
            if 'p' in box:
                break
            if handle.done():         # dead/failed agent: fail fast, don't
                break                 # poll a dead spawn for 14 minutes
            await asyncio.sleep(1)
    finally:
        # One-shot on every exit path: after capture it must not take a
        # second action; on timeout/error it must not be left running.
        if handle is not None:
            try:
                handle.cancel()
            except Exception:
                pass
        try:
            tool.undefine(tname)
        except Exception:
            pass
    if 'p' not in box:
        detail = ''
        try:
            detail = str(handle.output())[:400]
        except Exception:
            pass
        raise RuntimeError(f'agent {agent_name!r} produced no captured '
                           f'action before the spawn deadline. {detail}')
    return box['p']


def bind_context():
    """Capture the CALLING cell's live context (active python tool-bridge
    session + telemetry vars) once, at campaign launch."""
    global _capture_ctx
    _capture_ctx = contextvars.copy_context()


def agent_spawn(agent_name, prompt):
    """(agent, prompt) -> captured payload; safe from orchestrator threads.
    Each call gets its own shallow copy of the captured context, so
    concurrent target/translator spawns never share a Context entry."""
    import contextvars as _cv
    base = _capture_ctx or _cv.copy_context()
    ctx = base.copy()
    fut = ctx.run(asyncio.run_coroutine_threadsafe,
                  _do_spawn(agent_name, prompt), _loop)
    return fut.result(timeout=900)
