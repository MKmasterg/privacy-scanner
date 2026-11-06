# Privacy Scanner

A character-level C++17 scanner for the compiler homework's simplified email,
Iranian mobile phone, and IPv4 rules. It uses only the C++ standard library.

Build from this directory with a C++17 compiler:

```sh
mkdir -p build
c++ -std=c++17 -O2 -Wall -Wextra -Wpedantic src/main.cpp -o build/privacy-scanner
```

Or, with CMake 3.12 or newer:

```sh
cmake -S . -B build
cmake --build build
```

Run with one input path (any extension):

```sh
./build/privacy-scanner input.txt
```

The program writes `sanitized.txt` and `report.json` in the current working
directory, overwriting previous outputs. Run in another directory to choose
their location. The input remains unchanged; an input that aliases either output
is rejected. Outputs must be separate files, and output symbolic links are rejected.
Errors go to standard error with a nonzero exit status. Invalid
UTF-8 is rejected before either output is written. An output I/O failure can
leave a partial output file, so use results only after a successful exit.

Recognition follows these rules:

- Candidates are maximal runs of ASCII `A-Z a-z 0-9 . _ - @`.
  Consecutive trailing dots are set aside before validation and preserved.
  A whole candidate must match; an invalid candidate stays unchanged.
- Email local parts contain dot-separated segments. Each segment starts and
  ends with an ASCII letter or digit; `_` and `-` may appear inside. Domain
  labels start and end with a letter or digit, with hyphens allowed inside.
  There must be at least two labels, and the final label is at least two letters.
- Phones contain exactly eleven ASCII digits starting with `09`.
- IPv4 addresses contain four decimal components between `0` and `255`, each
  with one to three digits. A component's only permitted leading zero is `0`.

`src/main.cpp` implements deterministic state transitions by hand. The email
DFA tracks local segment boundaries and domain label endings, together with a
bounded TLD length and an all-letters flag. Phone states count the eleven
positions. IPv4 states track the component number, digit count, and bounded
numeric value. Any invalid transition rejects the whole candidate. The scanner
never revisits replacement text.

Other bytes, including Unicode text, tabs and punctuation, are copied verbatim.
The UTF-8 decoder counts Unicode code points for original positions: lines and
columns start at one, and a tab counts as one column. LF and CRLF each start a
new line; a lone CR counts as an ordinary character. Candidate lengths exclude
the trailing punctuation dots. Combining marks count individually.

Matches become `[EMAIL]`, `[PHONE]`, or `[IP]`. The JSON report contains only the
type and original position, in input order:

```json
{
  "total_detected": 1,
  "findings": [
    {"type": "EMAIL", "line": 1, "column": 1, "length": 13}
  ]
}
```

For example, `a@lab.example...` becomes `[EMAIL]...` with that report. No
matches produces `"total_detected": 0` and `"findings": []`, with byte-identical
sanitized text. The specification's `type` field is treated as a string (its
table incorrectly calls it an array).

Run the regression suite after building:

```sh
python3 tests/test_scanner.py build/privacy-scanner
```
