# Information Security Lab Template

A configurable, menu-driven Python template for practising encrypted records,
digital signatures, signed timestamps, encrypted search and homomorphic totals.
Adapt it to the requirements of each lab question.

## Run

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python expense_reporting_system.py
```

Edit `CONFIG`, `SCENARIO`, `PERMISSIONS`, `EMPLOYEES` and `TRUSTEES` near the top
of the program. Role menus follow `PERMISSIONS`. Collection closes manually.

- [Configuration and workflow guide](configuration.md)
- [Expense reporting practice question](question1.md)
- [Hospital billing practice question](question2.md)

Keys and records are generated locally in `exam_data/`, which is excluded from
Git. Initial threshold Paillier key generation can take time; later runs reuse
saved keys. This is an educational template, and role selection is simulated.
