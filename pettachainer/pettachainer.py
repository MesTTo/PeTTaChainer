import logging
import multiprocessing as mp
from pathlib import Path
import sys
import threading
import traceback
import uuid
from typing import List, Optional
import __main__

from petta import PeTTa

if __package__:
    from .pln_validator import check_query, check_stmt
else:  # Allow direct script execution: python pettachainer/pettachainer.py
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from pettachainer.pln_validator import check_query, check_stmt

logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(message)s",
    level=logging.INFO
)
logger = logging.getLogger(__name__)

LOADEDLIB = False
LOADED_LOCK = threading.Lock()


def get_language_spec(llm_focused: bool = True) -> str:
    return (Path(__file__).resolve().parent / ("LLM_RULE_SPEC.md" if llm_focused else "LANGUAGE_SPEC.md")).read_text(encoding="utf-8")


def _query_worker(added_atoms: List[str], kb: str, steps: int, atom: str, conn):
    try:
        handler = PeTTaChainer()
        handler.kb = kb
        if added_atoms:
            handler.add_atoms_no_check(added_atoms)
        atoms = handler.handler.process_metta_string(f"!(query {steps} {kb} {atom})")
        conn.send(("ok", atoms))
    except Exception as exc:  # pragma: no cover
        conn.send(("err", (exc.__class__.__name__, str(exc), traceback.format_exc())))
    finally:
        conn.close()


def _as_list(value) -> List[str]:
    return [value] if isinstance(value, str) else value


class PeTTaChainer:
    def __init__(self):
        global LOADEDLIB
        self.handler = PeTTa()
        self.kb = f"kb{uuid.uuid4().hex}"
        self._added_atoms: List[str] = []
        base_dir = Path(__file__).resolve().parent

        if LOADEDLIB:
            return
        with LOADED_LOCK:
            if LOADEDLIB:
                return
            metta_path = base_dir / "metta" / "petta_chainer.metta"
            logger.info("Loading MeTTa library from %s", metta_path)
            self.handler.load_metta_file(str(metta_path))
            LOADEDLIB = True

    def _evaluate(self, atom: str) -> str:
        result = self.handler.process_metta_string(f"!(eval {atom})")
        if isinstance(result, list):
            if not result:
                raise ValueError("PeTTa returned no results")
            result = result[0]
        return str(result).strip()

    @staticmethod
    def _validate(kind: str, raw_atom: str, evaluated_atom: str, checker) -> None:
        if checker(evaluated_atom) == 0.0:
            raise ValueError(
                f"Invalid evaluated PLN {kind}. input={raw_atom} evaluated={evaluated_atom}"
            )

    def add_atom(self, atom: str) -> str:
        evaluated_atom = self._evaluate(atom)
        self._validate("statement", atom, evaluated_atom, check_stmt)
        result = self.handler.process_metta_string(f"!(compileadd {self.kb} {evaluated_atom})")
        self._added_atoms.append(evaluated_atom)
        return result

    def add_atoms_no_check(self, atoms: List[str]) -> str:
        adds = [f"(compileadd {self.kb} {atom})" for atom in atoms]
        result = self.handler.process_metta_string(
            f"!(superpose ({' '.join(adds)}))"
        )
        self._added_atoms.extend(atoms)
        return result

    evaluate_statement = _evaluate
    evaluate_query = _evaluate

    def print_kb(self):
        for atom in _as_list(self.handler.process_metta_string(f"!(match &kb $a (pretty $a))")):
            print(atom)

    def query(self, atom: str, steps: int = 100, timeout_sec: Optional[float] = 10) -> List[str]:
        evaluated_query = self._evaluate(atom)
        self._validate("query", atom, evaluated_query, check_query)

        if timeout_sec is None or timeout_sec <= 0:
            return _as_list(
                self.handler.process_metta_string(f"!(query {steps} {self.kb} {evaluated_query})")
            )

        main_file = getattr(__main__, "__file__", None)
        if not main_file or main_file == "<stdin>":
            logger.warning(
                "Multiprocessing query timeout is unavailable from %s; running query without a timeout",
                main_file or "interactive __main__",
            )
            return _as_list(
                self.handler.process_metta_string(f"!(query {steps} {self.kb} {evaluated_query})")
            )

        # Use a fresh spawned process so we don't inherit a live SWI/Janus runtime.
        ctx = mp.get_context("spawn")
        parent_conn, child_conn = ctx.Pipe(duplex=False)
        worker = ctx.Process(
            target=_query_worker,
            args=(self._added_atoms, self.kb, steps, evaluated_query, child_conn),
            daemon=True,
        )
        worker.start()
        child_conn.close()
        worker.join(timeout_sec)

        if worker.is_alive():
            worker.terminate()
            worker.join()
            parent_conn.close()
            raise TimeoutError(f"PeTTa query timed out after {timeout_sec} seconds")

        try:
            if not parent_conn.poll():
                raise RuntimeError("PeTTa query worker exited without returning a result")
            status, payload = parent_conn.recv()
            if status == "ok":
                return payload
            err_type, err_msg, err_tb = payload
            raise RuntimeError(f"PeTTa query worker failed [{err_type}]: {err_msg}\n{err_tb}")
        finally:
            parent_conn.close()

    language_spec = staticmethod(get_language_spec)


if __name__ == "__main__":
    handler = PeTTaChainer()
    atom = "(: fact_a (Count A 1) (STV 1.0 1.0))"
    print(f"Adding {atom}")
    print(handler.add_atom(atom))
    print("Query result:")
    print(handler.query("(: $prf (Count A 1) $tv)", timeout_sec=0))
