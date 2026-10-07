"""checker 모듈 테스트."""

from src.checker import (
    MIN_LENGTH,
    RECOMMENDED_LENGTH,
    check_rules,
    generate_strong_password,
    get_grade,
)


def test_all_rules_passed() -> None:
    assert all(check_rules("Abcdef1!").values())


def test_no_rules_passed() -> None:
    assert not any(check_rules("").values())


def test_mixed_case_required() -> None:
    results = check_rules("abcdefgh")
    assert results["8자리 이상"] is True
    assert results["대문자와 소문자 혼합"] is False


def test_grades() -> None:
    assert get_grade(0)[0] == "취약"
    assert get_grade(1)[0] == "취약"
    assert get_grade(2)[0] == "보통"
    assert get_grade(3)[0] == "보통"
    assert get_grade(4)[0] == "강력"


def test_generated_password_is_strong() -> None:
    for _ in range(100):
        password = generate_strong_password()
        assert len(password) == RECOMMENDED_LENGTH
        assert get_grade(sum(check_rules(password).values()))[0] == "강력"


def test_generated_password_is_random() -> None:
    assert len({generate_strong_password() for _ in range(20)}) == 20


def test_generate_rejects_short_length() -> None:
    try:
        generate_strong_password(MIN_LENGTH - 1)
    except ValueError:
        return
    raise AssertionError("ValueError가 발생해야 합니다.")
