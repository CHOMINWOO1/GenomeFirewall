# GenomeFirewall: 실험 결과와 진행 상태

이 문서는 공개본에 보존된 실험·검증 기록을 시각화한 것이다. 원래 학습·과학 실험을 새로 수행했다는 의미는 아니다. 기능 테스트, 합성 데모, 실제 성능 지표를 서로 구분한다. 진행률의 임의 퍼센트는 사용하지 않는다.

![실험 및 검증 요약](results.png)

## 결과 해석

A1과 A2에서 일부 실행이 차단됐지만 보고된 올바른 추론 수는 각각 3/3이었다. 차단 횟수를 개인정보 보호 성공률로 바꾸어 해석하면 안 된다. 실제 외부 LLM 경로는 실행되지 않았다.

## 현재 진행 상태

| 항목 | 확인된 상태 |
|---|---|
| 질의·공격·ledger 정책 | 구현 및 합성 pilot 실행 |
| 공개본 테스트 | 89개 통과 |
| 실제 provider 공격 | 미실행 |
| 실데이터·공격 다양성·효용 | 추가 평가 필요 |

## 다음 보완 과제

1. 같은 질의 예산의 공격자 비교와 정상 질의 효용 측정
2. 실제 모델을 사용하는 적응형 공격의 통제된 실행
3. 정책 우회와 누적 정보 노출에 대한 추가 평가

## 보안 범위와 남은 검증

Ledger 규칙은 완전한 보안 증명이나 differential privacy 보장이 아니다. 평문 fallback을 암호화 검증으로 표시하지 않으며 provider 실행 여부를 따로 기록한다.
`.gitignore` 외에 공개 파일 내용도 검사했다. 이전에 유출된 비밀정보를 ignore 규칙만으로 회수할 수는 없다.

## 근거와 그림 재현

- [docs/experiments/a0_a1_a2_comparison_report.md](../../docs/experiments/a0_a1_a2_comparison_report.md)
- [VALIDATION.md](../../VALIDATION.md)
- [그림의 수치와 조건](metrics.json)
- [확대 가능한 SVG](results.svg)
- [그림 재생성 코드](reproduce_figures.py)

```bash
python -m pip install matplotlib
python docs/portfolio-results/reproduce_figures.py
```

원시 실험 재현은 각 프로젝트의 본문 프로토콜을 따른다. 위 명령은 보존된 수치로 그림만 다시 만든다.
