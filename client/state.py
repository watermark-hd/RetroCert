"""ローカルのインストール状態を管理する

RetroCertが自分で追加した証明書だけを記録しておくことで、
ユーザーが元々持っていた証明書を誤って削除しないようにする。
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone

import config


@dataclass
class InstalledEntry:
    common_name: str
    sha256: str
    installed_at: str


@dataclass
class State:
    last_version: str | None = None
    installed_by_retrocert: list[InstalledEntry] = field(default_factory=list)


def load_state() -> State:
    if not config.STATE_FILE.exists():
        return State()
    data = json.loads(config.STATE_FILE.read_text(encoding="utf-8"))
    entries = [InstalledEntry(**e) for e in data.get("installed_by_retrocert", [])]
    return State(last_version=data.get("last_version"), installed_by_retrocert=entries)


def save_state(state: State) -> None:
    config.STATE_DIR.mkdir(parents=True, exist_ok=True)
    data = {
        "last_version": state.last_version,
        "installed_by_retrocert": [asdict(e) for e in state.installed_by_retrocert],
    }
    config.STATE_FILE.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def record_install(state: State, common_name: str, sha256: str) -> None:
    now = datetime.now(timezone.utc).isoformat()
    state.installed_by_retrocert.append(
        InstalledEntry(common_name=common_name, sha256=sha256, installed_at=now)
    )


def record_removal(state: State, common_name: str) -> None:
    state.installed_by_retrocert = [
        e for e in state.installed_by_retrocert if e.common_name != common_name
    ]
