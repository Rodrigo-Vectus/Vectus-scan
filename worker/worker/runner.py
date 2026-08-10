import os
import subprocess
from dataclasses import dataclass

from worker.commands import ToolSpec


@dataclass
class RunResult:
    exit_code: int
    raw_path: str | None
    log_path: str


def real_runner(spec: ToolSpec, out_dir: str) -> RunResult:
    """Ejecuta la herramienta y persiste su salida cruda.

    - `capture_stdout=True`: el stdout se vuelca a `spec.output_path`.
    - `capture_stdout=False`: la herramienta escribe su propio archivo
      (nmap -oX, nuclei -o, etc.); igual guardamos stdout/stderr en un .log.

    Nunca usa shell: `subprocess.run` recibe la lista de argumentos tal cual.
    """
    os.makedirs(out_dir, exist_ok=True)
    log_path = os.path.join(out_dir, f"{spec.name}.log")

    try:
        with open(log_path, "wb") as logf:
            if spec.capture_stdout:
                with open(spec.output_path, "wb") as outf:
                    proc = subprocess.run(
                        spec.argv, stdout=outf, stderr=logf, timeout=spec.timeout
                    )
            else:
                proc = subprocess.run(
                    spec.argv, stdout=logf, stderr=logf, timeout=spec.timeout
                )
        exit_code = proc.returncode
    except subprocess.TimeoutExpired:
        exit_code = 124  # convención estándar de timeout
    except FileNotFoundError:
        exit_code = 127  # herramienta no encontrada

    raw = spec.output_path if os.path.exists(spec.output_path) else None
    return RunResult(exit_code=exit_code, raw_path=raw, log_path=log_path)
