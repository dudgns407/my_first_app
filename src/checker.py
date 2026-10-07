"""비밀번호 보안 등급을 평가하는 프로그램."""

import getpass
import os
import secrets
import string

SPECIAL_CHARS = "!@#$%^&*"
MIN_LENGTH = 8
RECOMMENDED_LENGTH = 12

# ANSI 색상 코드
RESET = "\033[0m"
BOLD = "\033[1m"
RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
GRAY = "\033[90m"


def check_rules(password: str) -> dict[str, bool]:
    """비밀번호가 각 검사 규칙을 충족하는지 확인한다.

    Args:
        password: 검사할 비밀번호.

    Returns:
        규칙 설명을 키로, 충족 여부를 값으로 하는 딕셔너리.
    """
    return {
        f"{MIN_LENGTH}자리 이상": len(password) >= MIN_LENGTH,
        "대문자와 소문자 혼합": any(c.isupper() for c in password)
        and any(c.islower() for c in password),
        "숫자 포함": any(c.isdigit() for c in password),
        f"특수문자({SPECIAL_CHARS}) 포함": any(c in SPECIAL_CHARS for c in password),
    }


def get_grade(passed_count: int) -> tuple[str, str, str]:
    """충족한 규칙 개수에 따라 보안 등급을 반환한다.

    Args:
        passed_count: 충족한 규칙 개수 (0~4).

    Returns:
        (등급 이름, 아이콘, ANSI 색상 코드) 튜플.
    """
    if passed_count <= 1:
        return "취약", "🔴", RED
    if passed_count <= 3:
        return "보통", "🟡", YELLOW
    return "강력", "🟢", GREEN


def generate_strong_password(length: int = RECOMMENDED_LENGTH) -> str:
    """'강력' 등급의 모든 규칙을 충족하는 무작위 비밀번호를 생성한다.

    대문자, 소문자, 숫자, 특수문자를 각각 최소 1개씩 포함하며,
    암호학적으로 안전한 난수(secrets)를 사용한다.

    Args:
        length: 생성할 비밀번호 길이. MIN_LENGTH 이상이어야 한다.

    Returns:
        생성된 비밀번호.

    Raises:
        ValueError: length가 MIN_LENGTH보다 작은 경우.
    """
    if length < MIN_LENGTH:
        raise ValueError(f"비밀번호 길이는 {MIN_LENGTH} 이상이어야 합니다.")

    groups = [string.ascii_uppercase, string.ascii_lowercase, string.digits, SPECIAL_CHARS]
    all_chars = "".join(groups)

    chars = [secrets.choice(group) for group in groups]
    chars += [secrets.choice(all_chars) for _ in range(length - len(groups))]
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


def print_recommendation() -> None:
    """'강력' 등급의 추천 비밀번호를 생성해 출력한다."""
    recommended = generate_strong_password()
    print(f"  💡 추천 비밀번호 ({GREEN}강력{RESET} 등급)")
    print(f"     {BOLD}{GREEN}{recommended}{RESET}")
    print(f"{BOLD}{'=' * 36}{RESET}")
    print()


def print_report(password: str) -> None:
    """비밀번호 검사 결과를 색상과 아이콘으로 꾸며 출력한다.

    Args:
        password: 검사할 비밀번호. 비밀번호 자체는 출력하지 않는다.
    """
    results = check_rules(password)
    passed_count = sum(results.values())
    grade, icon, color = get_grade(passed_count)
    total = len(results)

    print()
    print(f"{BOLD}{'=' * 36}{RESET}")
    print(f"{BOLD}   🔐 비밀번호 보안 검사 결과{RESET}")
    print(f"{BOLD}{'=' * 36}{RESET}")
    for rule, passed in results.items():
        if passed:
            print(f"  {GREEN}✅ {rule}{RESET}")
        else:
            print(f"  {GRAY}❌ {rule}{RESET}")
    print(f"{'-' * 36}")

    bar = "■" * passed_count + "□" * (total - passed_count)
    print(f"  충족 조건 : {color}{bar}{RESET} ({passed_count}/{total})")
    print(f"  보안 등급 : {icon} {BOLD}{color}{grade}{RESET}")
    print(f"{'-' * 36}")


def main() -> None:
    """사용자에게 비밀번호를 입력받아 보안 등급을 출력한다."""
    os.system("")  # Windows 터미널에서 ANSI 색상 활성화
    password = getpass.getpass("검사할 비밀번호를 입력하세요 (입력 내용은 보이지 않습니다): ")
    print_report(password)
    print_recommendation()


if __name__ == "__main__":
    main()
