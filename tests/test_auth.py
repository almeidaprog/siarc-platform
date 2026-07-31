import os

from fastapi import HTTPException

from scripts.siarc_api import verify_api_key


def test_rejects_when_server_key_not_configured():
    os.environ.pop("SIARC_API_KEY", None)
    try:
        verify_api_key(x_api_key="qualquer-coisa")
        raise AssertionError("deveria ter levantado HTTPException 503")
    except HTTPException as exc:
        assert exc.status_code == 503


def test_rejects_wrong_or_missing_key():
    os.environ["SIARC_API_KEY"] = "chave-correta"
    for bad in ("", "chave-errada"):
        try:
            verify_api_key(x_api_key=bad)
            raise AssertionError("deveria ter levantado HTTPException 401")
        except HTTPException as exc:
            assert exc.status_code == 401


def test_accepts_correct_key():
    os.environ["SIARC_API_KEY"] = "chave-correta"
    verify_api_key(x_api_key="chave-correta")  # não deve levantar exceção


if __name__ == "__main__":
    test_rejects_when_server_key_not_configured()
    test_rejects_wrong_or_missing_key()
    test_accepts_correct_key()
    print("Testes de autenticação concluídos.")
