"""Live CyberGym extension for the SoundTrace direct pipeline.

Submodules:
    corpus            strict soundtrace-cybergym-corpus-v1 loader/writer
    cybergym_backend  trusted Docker/ASan capture backend (+ bootstrap/qualify)
    cybergym_adapter  cybergym-asan-v1 admission (five facts, frozen target)
    openai_responses  stdlib OpenAI Responses API client
    translator        live visible-chunk -> primitive-step translator
    orchestrator      sandboxed target-agent loop + broker + scoring

The package deliberately keeps `runner.py`, `frontend.py`, `checker.py`, and
`direct.py` as the sole proof/HMAC/kernel boundary; nothing here weakens them.
"""
