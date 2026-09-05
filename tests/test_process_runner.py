"""进程执行器进程树托管测试 (P0 行动项 #4 / ADR-2)。

验证 _default_process_runner 的进程组托管:
1. 超时后整棵进程树被终止 (含工具内部再起的孙进程);
2. Windows 下 AICP 进程被强杀时, Job Object 让内核终止整棵进程树
   (孤儿孙进程继续对目标发包 = 超出授权范围的合规风险, 必须封死)。

本文件会启动真实 python 子进程 (不依赖外部工具二进制、零网络),
用 psutil 断言进程树状态 —— psutil 仅测试使用, 运行时零新依赖。
"""

from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path

import psutil
import pytest

from aicp import cli as cli_module
from aicp.cli import _default_process_runner


_PROJECT_ROOT = Path(cli_module.__file__).resolve().parents[2]


def _write_sleep_script(path: Path, seconds: int = 60) -> Path:
    path.write_text(f"import time\ntime.sleep({seconds})\n", encoding="utf-8")
    return path


def _spawn_tree_parent(path: Path, grandchild: Path) -> Path:
    """父脚本: 启动孙进程后长眠 (模拟 OneForAll 内部再起 httpx)。"""
    path.write_text(
        "import subprocess, sys, time\n"
        f"subprocess.Popen([sys.executable, r'{grandchild}'])\n"
        "time.sleep(60)\n",
        encoding="utf-8",
    )
    return path


def _any_process_running(script: Path) -> bool:
    """是否存在命令行含指定脚本路径的存活进程。"""
    target = str(script)
    for p in psutil.process_iter(["cmdline"]):
        try:
            cmdline = " ".join(p.info["cmdline"] or [])
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
        if target in cmdline:
            return True
    return False


def _wait_until(cond, timeout_s: float = 10.0, interval_s: float = 0.2) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if cond():
            return True
        time.sleep(interval_s)
    return cond()


@pytest.mark.recovery
def test_runner_timeout_kills_whole_process_tree(tmp_path, monkeypatch):
    """行动项 #4: 超时后整棵进程树终止, 孙进程不残留。

    旧实现 subprocess.run 超时只 kill 直接子进程, 孙进程成孤儿继续跑。
    """
    monkeypatch.setattr(cli_module, "_SUBPROCESS_TIMEOUT_S", 2)

    grandchild = _write_sleep_script(tmp_path / "grandchild.py")
    parent = _spawn_tree_parent(tmp_path / "parent.py", grandchild)

    proc = _default_process_runner([sys.executable, str(parent)], str(tmp_path))

    # 超时返回 rc=-1 + 明确错误信息
    assert proc.returncode == -1
    assert "超时" in proc.stderr
    assert "进程树" in proc.stderr
    # 孙进程被整树终止 (而非孤儿存活 60s)
    assert _wait_until(lambda: not _any_process_running(grandchild))


@pytest.mark.recovery
@pytest.mark.skipif(sys.platform != "win32", reason="Job Object 为 Windows 原生机制")
def test_job_object_kills_tree_when_parent_dies(tmp_path):
    """行动项 #4 (DoD): 强杀 AICP 进程后, 孙进程随 Job Object 被内核终止。

    模拟: wrapper 进程用 _default_process_runner 起了工具树,
    随后被 kill -9 (psutil kill = TerminateProcess, 不执行任何 Python 清理)。
    """
    grandchild = _write_sleep_script(tmp_path / "grandchild.py")
    parent = _spawn_tree_parent(tmp_path / "parent.py", grandchild)

    wrapper = tmp_path / "wrapper.py"
    wrapper.write_text(
        "import sys\n"
        f"sys.path.insert(0, r'{_PROJECT_ROOT}')\n"
        "from aicp.cli import _default_process_runner\n"
        f"_default_process_runner([sys.executable, r'{parent}'], r'{tmp_path}')\n",
        encoding="utf-8",
    )

    wrapper_proc = psutil.Popen(
        [sys.executable, str(wrapper)], cwd=str(tmp_path),
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        # 等孙进程确实起来了 (否则测试空转)
        assert _wait_until(lambda: _any_process_running(grandchild)), "孙进程未启动"

        # 强杀 wrapper (等价 kill -9: 无 atexit / 无 Python 层清理)
        wrapper_proc.kill()
        wrapper_proc.wait(timeout=10)
    finally:
        if wrapper_proc.is_running():
            wrapper_proc.kill()

    # wrapper 死后内核经 Job Object 终止整棵树: 孙进程应消失
    assert _wait_until(lambda: not _any_process_running(grandchild)), (
        "孙进程在父进程强杀后仍存活 (孤儿继续扫描 = 合规风险)"
    )


def test_runner_normal_completion(tmp_path):
    """正常完成路径: rc/stdout/stderr 透传 (回归)。"""
    script = tmp_path / "ok.py"
    script.write_text("print('hello-out')\n", encoding="utf-8")

    proc = _default_process_runner([sys.executable, str(script)], str(tmp_path))

    assert proc.returncode == 0
    assert "hello-out" in proc.stdout
