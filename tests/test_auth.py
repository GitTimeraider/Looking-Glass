import pyotp

from lookingglass import auth


def test_password_hash_roundtrip():
    h = auth.hash_password("correct horse battery")
    assert h.startswith("scrypt$")
    assert auth.verify_password("correct horse battery", h)
    assert not auth.verify_password("wrong", h)
    assert not auth.verify_password("x", "garbage")


def test_password_policy():
    assert auth.password_problem("short")
    assert auth.password_problem("aaaaaaaaaaaa")
    assert auth.password_problem("Good-Password-1") is None


def test_totp_and_replay():
    secret = auth.new_totp_secret()
    code = pyotp.TOTP(secret).now()
    assert auth.verify_totp(secret, code, user_id=42)
    assert not auth.verify_totp(secret, code, user_id=42)  # replay rejected
    assert not auth.verify_totp(secret, "abc", user_id=44)


def test_reset_code(caplog):
    auth._reset.clear()
    with caplog.at_level("WARNING", logger="lookingglass.auth"):
        auth.create_reset_code("admin")
    code = next(r.getMessage().split("Reset code: ")[1].split()[0] for r in caplog.records if "Reset code:" in r.getMessage())
    assert auth.check_reset_code("WRONG-CODE") is None
    assert auth.check_reset_code(code.lower().replace("-", "")) == "admin"  # case / dash insensitive
    assert auth.check_reset_code(code) is None  # single use


def test_reset_code_attempt_limit(caplog):
    auth._reset.clear()
    with caplog.at_level("WARNING", logger="lookingglass.auth"):
        auth.create_reset_code("admin")
    code = next(r.getMessage().split("Reset code: ")[1].split()[0] for r in caplog.records if "Reset code:" in r.getMessage())
    for _ in range(5):
        auth.check_reset_code("0000-0000")
    assert auth.check_reset_code(code) is None  # burned after 5 wrong attempts
