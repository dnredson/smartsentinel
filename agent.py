#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Agente de monitoramento:
- Sistema: CPU/RAM/DISCO
- Rede: latência (ICMP via ping; fallback TCP 443)
- Processos: por nomes definidos no config
- Docker: todos containers em execução (CPU%, MEM%, status, RX/TX, PIDs)
- Saídas: Firestore (Firebase) e/ou CSV local
- DLQ: salvamento de erros em JSONL

Config TOML (exemplo):
[agent]
device_id = "edge-node-01"
sample_interval_sec = 30
ping_count = 3
dlq_path = "/var/lib/monitor-agent/dlq"

[target]
ip = "8.8.8.8"

[processes]
names = ["mosquitto", "python", "chrome"]

[docker]
enable = true
timeout_sec = 3

[firebase]
enable = true
project_id = "SEU_PROJECT_ID"
credentials_json_path = "/etc/monitor-agent/service-account.json"
collection = "telemetry"

[local_csv]
enable = true
path = "/var/lib/monitor-agent/samples.csv"
rotate_by_size_mb = 50
keep_rotations = 5
"""
from __future__ import annotations

import csv
import json
import os
import platform
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone
from math import isfinite
from pathlib import Path
from typing import Dict, Any, List, Tuple

import psutil

# TOML loader (3.11+ tem tomllib nativo)
try:
    import tomllib  # Python 3.11+
except ModuleNotFoundError:
    import tomli as tomllib  # Python <=3.10


# ----------------------- Utils & Infra ----------------------------------------
def load_config(path: str) -> Dict[str, Any]:
    with open(path, "rb") as f:
        return tomllib.load(f)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def ensure_dir(p: str):
    if p:
        Path(p).mkdir(parents=True, exist_ok=True)


def init_firebase(project_id: str | None, cred_path: str | None):
    """
    Inicializa Firestore client sob demanda. Só chame se [firebase].enable = true.
    Evita import se não for usar.
    """
    if not project_id:
        raise ValueError("firebase.project_id não definido")
    try:
        import firebase_admin  # type: ignore
        from firebase_admin import credentials, firestore  # type: ignore

        if not firebase_admin._apps:
            if cred_path and os.path.exists(cred_path):
                cred = credentials.Certificate(cred_path)
                firebase_admin.initialize_app(cred, {"projectId": project_id})
            else:
                # Tenta credencial via GOOGLE_APPLICATION_CREDENTIALS / metadata
                firebase_admin.initialize_app()
        return firestore.client()
    except ImportError as e:
        raise RuntimeError(
            "Biblioteca firebase-admin não instalada. "
            "Defina [firebase].enable = false ou instale 'firebase-admin'."
        ) from e


# ----------------------- Ping / Latência --------------------------------------
def parse_ping_output(output: str) -> Tuple[float, float, float]:
    """
    Retorna (min_ms, avg_ms, max_ms).
    Compatível com Linux/macOS ("min/avg/max") e Windows ("Minimum/Maximum/Average").
    """
    out = output.replace(",", ".")
    low = out.lower()

    # Linux/macOS: linha com "min/avg/max"
    for line in out.splitlines():
        if "min/avg/max" in line:
            parts = line.split("=")[-1].strip().split("/")
            mn, av, mx = float(parts[0]), float(parts[1]), float(parts[2])
            return mn, av, mx

    # Windows: "... Minimum = 13ms, Maximum = 28ms, Average = 17ms"
    if "average" in low and "minimum" in low and "maximum" in low:
        def take_num(s: str) -> float:
            num = "".join(ch for ch in s if (ch.isdigit() or ch == "."))
            return float(num) if num else float("nan")

        # usa o texto original para não quebrar índices
        min_part = out.lower().split("minimum", 1)[-1]
        max_part = out.lower().split("maximum", 1)[-1]
        avg_part = out.lower().split("average", 1)[-1]
        mn = take_num(min_part)
        mx = take_num(max_part)
        av = take_num(avg_part)
        if all(isfinite(x) for x in (mn, av, mx)):
            return mn, av, mx

    raise ValueError("Não foi possível interpretar a saída do ping.")


def ping_latency(host: str, count: int = 3, timeout_sec: int = 2) -> Dict[str, Any]:
    """
    Faz ICMP ping via utilitário do SO (cross-platform).
    Se falhar, fallback: mede tempo de conexão TCP (porta 443).
    """
    is_windows = platform.system().lower().startswith("win")
    try:
        if is_windows:
            # -n <count>, -w timeout_ms
            cmd = ["ping", host, "-n", str(count), "-w", str(int(timeout_sec * 1000))]
        else:
            # -c <count>, -W timeout (Linux=seg; macOS difere, mas mantemos curto)
            cmd = ["ping", "-c", str(count), "-W", str(timeout_sec), host]

        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=(timeout_sec * count + 3)
        )
        out = (result.stdout or result.stderr or "").strip()
        mn, av, mx = parse_ping_output(out)
        return {
            "method": "icmp",
            "success": (result.returncode == 0),
            "min_ms": mn,
            "avg_ms": av,
            "max_ms": mx,
            "raw": out[:5000],
        }
    except Exception:
        # Fallback TCP connect timing (porta 443)
        t0 = time.perf_counter()
        ok = False
        try:
            with socket.create_connection((host, 443), timeout_sec):
                ok = True
        except Exception:
            ok = False
        dt_ms = (time.perf_counter() - t0) * 1000.0
        return {
            "method": "tcp_connect_443",
            "success": ok,
            "avg_ms": dt_ms,
        }


# ----------------------- Métricas de Sistema/Processos ------------------------
def collect_system_metrics() -> Dict[str, Any]:
    cpu_percent = psutil.cpu_percent(interval=None)
    vm = psutil.virtual_memory()
    try:
        du_root = psutil.disk_usage("/")
    except Exception:
        # Windows pode usar drive atual se "/" falhar
        du_root = psutil.disk_usage(os.getcwd())
    boot_time = datetime.fromtimestamp(psutil.boot_time(), tz=timezone.utc).isoformat()

    return {
        "cpu_percent": cpu_percent,
        "ram_percent": vm.percent,
        "ram_total_bytes": vm.total,
        "ram_used_bytes": vm.used,
        "disk_root_percent": du_root.percent,
        "disk_root_total_bytes": du_root.total,
        "disk_root_used_bytes": du_root.used,
        "boot_time": boot_time,
    }


def summarize_proc_status(p: psutil.Process) -> str:
    try:
        return p.status()
    except Exception:
        return "unknown"


def collect_process_metrics(names: List[str]) -> Dict[str, Any]:
    """
    Agrega por nome (substring case-insensitive).
    Para cada nome: soma CPU%, soma RSS, conta instâncias, estados únicos e PIDs.
    """
    wanted = [n.lower() for n in names]
    agg: Dict[str, Dict[str, Any]] = {
        n: {"instances": 0, "cpu_percent_sum": 0.0, "rss_bytes_sum": 0, "states": set(), "pids": []}
        for n in wanted
    }

    for p in psutil.process_iter(attrs=["name", "pid", "memory_info"]):
        try:
            pname = (p.info.get("name") or "").lower()
            for target in wanted:
                if target and target in pname:
                    agg[target]["instances"] += 1
                    agg[target]["cpu_percent_sum"] += p.cpu_percent(interval=None)
                    mi = p.info.get("memory_info")
                    if mi:
                        agg[target]["rss_bytes_sum"] += getattr(mi, "rss", 0)
                    agg[target]["states"].add(summarize_proc_status(psutil.Process(p.info["pid"])))
                    agg[target]["pids"].append(p.info["pid"])
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    out: Dict[str, Any] = {}
    for k, v in agg.items():
        out[k] = {
            "instances": v["instances"],
            "cpu_percent_total": round(v["cpu_percent_sum"], 2),
            "rss_bytes_total": v["rss_bytes_sum"],
            "states": sorted(list(v["states"])) if v["states"] else [],
            "pids": v["pids"],
        }
    return out


# ----------------------- Docker Monitoring ------------------------------------
def _calc_cpu_percent_from_stats(stats: Dict[str, Any]) -> float | None:
    try:
        cpu = stats.get("cpu_stats", {}) or {}
        precpu = stats.get("precpu_stats", {}) or {}
        cpu_total = ((cpu.get("cpu_usage") or {}).get("total_usage") or 0)
        pre_total = ((precpu.get("cpu_usage") or {}).get("total_usage") or 0)
        cpu_delta = cpu_total - pre_total

        sys_total = cpu.get("system_cpu_usage") or 0
        pre_sys = precpu.get("system_cpu_usage") or 0
        sys_delta = sys_total - pre_sys

        online = cpu.get("online_cpus")
        if not online:
            per_cpu = (cpu.get("cpu_usage") or {}).get("percpu_usage") or []
            online = len(per_cpu) or 1

        if cpu_delta > 0 and sys_delta > 0:
            return (cpu_delta / sys_delta) * online * 100.0
    except Exception:
        pass
    return None


def collect_docker_metrics(enable: bool = True, timeout_sec: int = 3) -> Dict[str, Any]:
    """
    Coleta métricas de TODOS os containers em execução:
    id, name, image, status, startedAt, cpu%, mem%, mem bytes, PIDs, RX/TX.
    """
    if not enable:
        return {"enabled": False}

    try:
        import docker  # type: ignore
        from docker.errors import DockerException, APIError  # type: ignore

        client = docker.from_env()
        containers = client.containers.list(all=False)
        out_list: List[Dict[str, Any]] = []

        for c in containers:
            try:
                stats = c.stats(stream=False)
                cpu_percent = _calc_cpu_percent_from_stats(stats)

                mem = stats.get("memory_stats", {}) or {}
                mem_usage = mem.get("usage")
                mem_limit = mem.get("limit")
                mem_percent = (mem_usage / mem_limit * 100.0) if mem_usage and mem_limit else None

                # network io (todas as ifaces)
                rx = tx = 0
                for _, n in (stats.get("networks") or {}).items():
                    rx += int(n.get("rx_bytes") or 0)
                    tx += int(n.get("tx_bytes") or 0)

                # pids
                pids_current = None
                pids = stats.get("pids_stats") or {}
                if "current" in pids:
                    pids_current = pids.get("current")

                # estado/identidade
                try:
                    c.reload()
                except Exception:
                    pass
                state = (getattr(c, "attrs", {}) or {}).get("State", {}) or {}
                started_at = state.get("StartedAt")
                status = c.status

                out_list.append({
                    "id": c.id[:12],
                    "name": c.name,
                    "image": (c.image.tags[0] if getattr(c.image, "tags", []) else getattr(c.image, "short_id", "")),
                    "status": status,
                    "startedAt": started_at,

                    "cpu_percent": None if cpu_percent is None else round(cpu_percent, 2),
                    "mem_usage_bytes": mem_usage,
                    "mem_limit_bytes": mem_limit,
                    "mem_percent": None if mem_percent is None else round(mem_percent, 2),
                    "pids_current": pids_current,

                    "rx_bytes": rx,
                    "tx_bytes": tx,
                })
            except (APIError, DockerException, Exception) as e:
                out_list.append({
                    "id": c.id[:12],
                    "name": getattr(c, "name", "?"),
                    "error": f"{type(e).__name__}: {e}",
                })

        return {
            "enabled": True,
            "unavailable": False,
            "count_running": len(out_list),
            "containers": out_list,
        }

    except Exception as e:
        return {
            "enabled": True,
            "unavailable": True,
            "error": f"{type(e).__name__}: {e}",
        }


# ----------------------- Firestore / CSV / DLQ --------------------------------
def send_to_firestore(db, collection: str, device_id: str, payload: Dict[str, Any]):
    """
    Grava em collection/{device_id}/samples/{auto_id}
    """
    doc_ref = (
        db.collection(collection)
        .document(device_id)
        .collection("samples")
        .document()
    )
    doc_ref.set(payload)


def write_dlq(dlq_path: str, payload: Dict[str, Any]):
    ensure_dir(dlq_path)
    fn = os.path.join(dlq_path, "failed.jsonl")
    with open(fn, "a", encoding="utf-8") as f:
        f.write(json.dumps(payload, ensure_ascii=False) + "\n")


def _is_file(path: str) -> bool:
    try:
        return Path(path).is_file()
    except Exception:
        return False


def _rotate_file(path: str, rotate_by_size_mb: int, keep: int):
    if rotate_by_size_mb <= 0 or keep <= 0:
        return
    try:
        if not _is_file(path):
            return
        size_mb = os.path.getsize(path) / (1024 * 1024)
        if size_mb < rotate_by_size_mb:
            return
        # apaga o mais antigo
        oldest = f"{path}.{keep}"
        if os.path.exists(oldest):
            os.remove(oldest)
        # move .(n-1) -> .n
        for i in range(keep - 1, 0, -1):
            src = f"{path}.{i}"
            dst = f"{path}.{i+1}"
            if os.path.exists(src):
                os.rename(src, dst)
        # move atual -> .1
        os.rename(path, f"{path}.1")
    except Exception:
        # rotação é best-effort: não deve quebrar o agente
        pass


def _flatten_for_csv(payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Achata campos principais em colunas fixas e serializa blocos completos em *_json.
    """
    d = {
        "timestamp": payload.get("timestamp"),
        "device_id": payload.get("device_id"),
        "platform_system": ((payload.get("platform") or {}).get("system")),
        "platform_release": ((payload.get("platform") or {}).get("release")),
        "platform_machine": ((payload.get("platform") or {}).get("machine")),
    }
    sysm = payload.get("system") or {}
    d.update({
        "cpu_percent": sysm.get("cpu_percent"),
        "ram_percent": sysm.get("ram_percent"),
        "ram_total_bytes": sysm.get("ram_total_bytes"),
        "ram_used_bytes": sysm.get("ram_used_bytes"),
        "disk_root_percent": sysm.get("disk_root_percent"),
        "disk_root_total_bytes": sysm.get("disk_root_total_bytes"),
        "disk_root_used_bytes": sysm.get("disk_root_used_bytes"),
    })
    net = payload.get("network") or {}
    d.update({
        "net_method": net.get("method"),
        "net_success": net.get("success"),
        "net_avg_ms": net.get("avg_ms"),
        "net_min_ms": net.get("min_ms"),
        "net_max_ms": net.get("max_ms"),
    })
    procs = payload.get("processes") or {}
    d["processes_count"] = len(procs)
    dock = payload.get("docker") or {}
    d["docker_enabled"] = dock.get("enabled")
    d["docker_unavailable"] = dock.get("unavailable")
    d["docker_running"] = dock.get("count_running")

    # blocos detalhados
    d["network_json"] = json.dumps(net, ensure_ascii=False)
    d["processes_json"] = json.dumps(procs, ensure_ascii=False)
    d["docker_json"] = json.dumps(dock, ensure_ascii=False)
    d["payload_json"] = json.dumps(payload, ensure_ascii=False)
    return d


def write_csv_row(csv_path: str, rotate_by_size_mb: int, keep: int, payload: Dict[str, Any]):
    ensure_dir(os.path.dirname(csv_path) or ".")
    _rotate_file(csv_path, rotate_by_size_mb, keep)
    row = _flatten_for_csv(payload)
    new_file = not os.path.exists(csv_path)
    with open(csv_path, "a", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(row.keys()))
        if new_file:
            writer.writeheader()
        writer.writerow(row)


# ----------------------- Main Loop --------------------------------------------
def main():
    # --- args ---
    cfg_path = sys.argv[1] if len(sys.argv) > 1 else "config.toml"
    cfg = load_config(cfg_path)

    agent = cfg.get("agent", {})
    target = cfg.get("target", {})
    processes = cfg.get("processes", {})
    docker_cfg = cfg.get("docker", {})
    fb = cfg.get("firebase", {})
    local_csv_cfg = cfg.get("local_csv", {})

    device_id = agent.get("device_id", socket.gethostname())
    interval = int(agent.get("sample_interval_sec", 30))
    ping_count = int(agent.get("ping_count", 3))
    dlq_path = agent.get("dlq_path", "./dlq")

    host = target.get("ip", "8.8.8.8")
    proc_names = processes.get("names", [])

    # Saídas
    firebase_enabled = bool(fb.get("enable", True))
    collection = fb.get("collection", "telemetry")
    project_id = fb.get("project_id")
    cred_path = fb.get("credentials_json_path", "")

    csv_enabled = bool(local_csv_cfg.get("enable", False))
    csv_path = str(local_csv_cfg.get("path", "./samples.csv"))
    csv_rotate_mb = int(local_csv_cfg.get("rotate_by_size_mb", 0))
    csv_keep = int(local_csv_cfg.get("keep_rotations", 5))

    # Docker
    docker_enable = bool(docker_cfg.get("enable", True))
    docker_timeout = int(docker_cfg.get("timeout_sec", 3))

    # Inicializa Firebase se habilitado
    db = None
    if firebase_enabled:
        db = init_firebase(project_id, cred_path)

    # Prime para cpu_percent de processos
    for _ in range(2):
        for p in psutil.process_iter():
            try:
                p.cpu_percent(interval=None)
            except Exception:
                continue
        time.sleep(0.1)

    print(f"[agent] device={device_id} → target={host} interval={interval}s "
          f"| firebase={firebase_enabled} csv={csv_enabled} docker={docker_enable}")

    while True:
        ts = utc_now_iso()
        try:
            sys_metrics = collect_system_metrics()
            net_metrics = ping_latency(host, count=ping_count)
            proc_metrics = collect_process_metrics(proc_names)
            docker_metrics = collect_docker_metrics(enable=docker_enable, timeout_sec=docker_timeout)

            payload = {
                "timestamp": ts,
                "device_id": device_id,
                "platform": {
                    "system": platform.system(),
                    "release": platform.release(),
                    "machine": platform.machine(),
                },
                "system": sys_metrics,
                "network": net_metrics,
                "processes": proc_metrics,
                "docker": docker_metrics,
            }

            # --- Saídas ---
            if firebase_enabled and db is not None:
                send_to_firestore(db, collection, device_id, payload)
            if csv_enabled:
                write_csv_row(csv_path, csv_rotate_mb, csv_keep, payload)

            dests = []
            if firebase_enabled: dests.append("firebase")
            if csv_enabled: dests.append("csv")
            if not dests: dests.append("none")
            print(f"[ok] {ts} -> {' + '.join(dests)}")

        except Exception as e:
            err_payload = {
                "timestamp": ts,
                "device_id": device_id,
                "error": repr(e),
            }
            try:
                err_payload.update({
                    "last_system": sys_metrics,
                    "last_network": net_metrics,
                    "last_processes": proc_metrics,
                    "last_docker": docker_metrics if 'docker_metrics' in locals() else None,
                })
            except Exception:
                pass
            write_dlq(dlq_path, err_payload)
            print(f"[erro] {ts} → registrado na DLQ: {e}")

        time.sleep(max(1, interval))


if __name__ == "__main__":
    main()
