import asyncio
import os
import sys

EXPECTED_VERSION = "17.36"

import bot


def _fail(message: str):
    print(f"[MABOYY LAUNCHER ERROR] {message}", file=sys.stderr, flush=True)
    raise SystemExit(1)


def launcher_self_test():
    version = str(getattr(bot, "BOT_VERSION", "") or "")
    if version != EXPECTED_VERSION:
        _fail(
            f"bot.py version mismatch: got={version or '-'} expected={EXPECTED_VERSION}. "
            "Upload semua modul runtime dari paket versi yang sama ke root repository."
        )

    if not callable(getattr(bot, "main", None)):
        _fail("bot.main tidak ditemukan.")

    parser = getattr(bot, "parse_rupiah_input", None)
    if not callable(parser) or parser("Rp2.500") != 2500:
        _fail("Parser harga bot.py gagal self-test.")

    print(
        "[MABOYY LAUNCHER] "
        f"main.py -> bot.py v{version} | "
        f"deployment={os.getenv('RAILWAY_DEPLOYMENT_ID','-')} | "
        f"commit={os.getenv('RAILWAY_GIT_COMMIT_SHA','-')[:12] or '-'}",
        flush=True,
    )


if __name__ == "__main__":
    launcher_self_test()
    asyncio.run(bot.main())
