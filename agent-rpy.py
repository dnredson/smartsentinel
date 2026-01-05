import json
import os
import platform
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Tuple

import psutil

# TOML loader (3.11+ tem tomllib nativo)
try:
    import tomllib  # Python 3.11+
except ModuleNotFoundError:
    import tomli as tomllib  # Python <=3.10

# Firebase Admin
import firebase_admin
from firebase_admin import credentials, firestore


def load_config(path: str) -> Dict[str, Any]:
    with open(path, "rb") as f:
        return tomllib.load(f)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def ensure_dir(p: str):
    Path(p).mkdir(parents=True, exist_ok=True)


def init_firebase(project_id: str, cred_path: str):
    if not firebase_admin._apps:
        if cred_path and os.path.exists(cred_path):
            cred = credentials.Certificate(cred_path)
            firebase_admin.initialize_app(cred, {"projectId": project_id})
        else:
            # Usa GOOGLE_APPLICATION_CREDENTIALS se já estiver setado
            firebase_admin.initialize_app()
    return firestore.client()

# --- Docker monitoring -------------------------------------------------------
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
    - id, name, image, status, startedAt
    - cpu_percent, mem_usage_bytes, mem_limit_bytes, mem_percent
    - pids_current, rx_bytes, tx_bytes
    """
    if not enable:
        return {"enabled": False}

    try:
        import docker
        from docker.errors import DockerException, APIError

        client = docker.from_env()
        containers = client.containers.list(all=False)
        out_list: List[Dict[str, Any]] = []

        for c in containers:
            try:
                # snapshot de stats (usa precpu_stats para %)
                stats = c.stats(stream=False)
                cpu_percent = _calc_cpu_percent_from_stats(stats)

                mem = stats.get("memory_stats", {}) or {}
                mem_usage = mem.get("usage")
                mem_limit = mem.get("limit")
                mem_percent = (mem_usage / mem_limit * 100.0) if mem_usage and mem_limit else None

                # network io (soma todas as ifaces)
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
                    c.reload()  # atualiza attrs/status
                except Exception:
                    pass
                state = (getattr(c, "attrs", {}) or {}).get("State", {}) or {}
                started_at = state.get("StartedAt")
                status = c.status  # running/paused/exited...

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
        # Docker não instalado, sem permissão no socket, etc.
        return {
            "enabled": True,
            "unavailable": True,
            "error": f"{type(e).__name__}: {e}",
        }

def parse_ping_output(output: str) -> Tuple[float, float, float]:
    """
    Retorna (min_ms, avg_ms, max_ms). Levanta ValueError se não achar.
    Trata formatos Linux/macOS e Windows.
    """
    out = output.lower().replace(",", ".")
    # Linux/macOS: "min/avg/max/..."  ex: rtt min/avg/max/mdev = 14.345/20.123/31.998/...
    for line in out.splitlines():
        if "min/avg/max" in line:
            parts = line.split("=")[-1].strip().split("/")
            mn, av, mx = float(parts[0]), float(parts[1]), float(parts[2])
            return mn, av, mx

    # Windows: "Approximate round trip times in milli-seconds: Minimum = 13ms, Maximum = 28ms, Average = 17ms"
    if "average" in out and "minimum" in out and "maximum" in out:
        # extrai números
        def take_num(s: str) -> float:
            num = "".join(ch for ch in s if (ch.isdigit() or ch == "."))
            return float(num) if num else float("nan")

        min_part = out.split("minimum")[-1].split("\n")[0]
        max_part = out.split("maximum")[-1].split("\n")[0]
        avg_part = out.split("average")[-1].split("\n")[0]
        mn = take_num(min_part)
        mx = take_num(max_part)
        av = take_num(avg_part)
        if all(psutil._common.math.isfinite(x) for x in (mn, av, mx)):
            return mn, av, mx

    raise ValueError("Não foi possível interpretar a saída do ping.")


def ping_latency(host: str, count: int = 3, timeout_sec: int = 2) -> Dict[str, Any]:
    """
    Faz ICMP ping via utilitário do SO (cross-platform). Se falhar parsing,
    usa fallback medindo tempo de conexão TCP (porta 443).
    """
    is_windows = platform.system().lower().startswith("win")
    try:
        if is_windows:
            # -n <count>, -w timeout_ms
            cmd = ["ping", host, "-n", str(count), "-w", str(int(timeout_sec * 1000))]
        else:
            # -c <count>, -W timeout_sec (Linux). Em macOS: -W é em ms; mantém timeout geral curto
            cmd = ["ping", "-c", str(count), "-W", str(timeout_sec), host]

        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=(timeout_sec * count + 3)
        )
        success = result.returncode == 0
        out = result.stdout or result.stderr or ""

        mn, av, mx = parse_ping_output(out)
        return {
            "method": "icmp",
            "success": success,
            "min_ms": mn,
            "avg_ms": av,
            "max_ms": mx,
            "raw": out.strip()[:5000],
        }
    except Exception as e:
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


def collect_system_metrics() -> Dict[str, Any]:
    cpu_percent = psutil.cpu_percent(interval=None)
    vm = psutil.virtual_memory()
    du_root = psutil.disk_usage("/")
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
    Agrega por nome (case-insensitive). Para cada nome, soma CPU% e RSS,
    conta instâncias e reporta o 'pior' estado observado.
    """
    wanted = [n.lower() for n in names]
    agg: Dict[str, Dict[str, Any]] = {n: {
        "instances": 0,
        "cpu_percent_sum": 0.0,
        "rss_bytes_sum": 0,
        "states": set(),
        "pids": []
    } for n in wanted}

    for p in psutil.process_iter(attrs=["name", "pid", "memory_info"]):
        try:
            pname = (p.info.get("name") or "").lower()
            for target in wanted:
                if target and target in pname:
                    agg[target]["instances"] += 1
                    # cpu_percent(None) usa delta desde última chamada; bom chamar uma vez antes do loop externo no 1º ciclo
                    agg[target]["cpu_percent_sum"] += p.cpu_percent(interval=None)
                    mi = p.info.get("memory_info")
                    if mi:
                        agg[target]["rss_bytes_sum"] += getattr(mi, "rss", 0)
                    agg[target]["states"].add(summarize_proc_status(psutil.Process(p.info["pid"])))
                    agg[target]["pids"].append(p.info["pid"])
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    # formata saída
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


def send_to_firestore(
    db,
    collection: str,
    device_id: str,
    payload: Dict[str, Any],
):
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


def main():
    # --- args simples ---
    cfg_path = sys.argv[1] if len(sys.argv) > 1 else "config.toml"
    cfg = load_config(cfg_path)

    agent = cfg.get("agent", {})
    target = cfg.get("target", {})
    processes = cfg.get("processes", {})
    fb = cfg.get("firebase", {})

    docker_cfg = cfg.get("docker", {})
    docker_enable = bool(docker_cfg.get("enable", True))
    docker_timeout = int(docker_cfg.get("timeout_sec", 3))
    
    device_id = agent.get("device_id", socket.gethostname())
    interval = int(agent.get("sample_interval_sec", 30))
    ping_count = int(agent.get("ping_count", 3))
    dlq_path = agent.get("dlq_path", "./dlq")

    host = target.get("ip", "8.8.8.8")
    proc_names = processes.get("names", [])

    project_id = fb.get("project_id")
    cred_path = fb.get("credentials_json_path", "")
    collection = fb.get("collection", "telemetry")

    # Inicializa Firebase
    db = init_firebase(project_id, cred_path)

    # Chamada “prime” para cpu_percent ter baseline dos processos
    for _ in range(2):
        for p in psutil.process_iter():
            try:
                p.cpu_percent(interval=None)
            except Exception:
                continue
        time.sleep(0.1)

    print(f"[agent] device={device_id} → target={host} interval={interval}s")
    while True:
        ts = utc_now_iso()
        try:
            sys_metrics = collect_system_metrics()
            net_metrics = ping_latency(host, count=ping_count)
            proc_metrics = collect_process_metrics(proc_names)
            docker_metrics = collect_docker_metrics(
                enable=docker_enable,
                timeout_sec=docker_timeout
            )
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

            send_to_firestore(db, collection, device_id, payload)
            print(f"[ok] {ts} enviado.")

        except Exception as e:
            err_payload = {
                "timestamp": ts,
                "device_id": device_id,
                "error": repr(e),
            }
            # se possível, agregue contexto
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
