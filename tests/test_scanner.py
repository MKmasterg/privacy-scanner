#!/usr/bin/env python3
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCANNER = Path(sys.argv.pop(1)).resolve() if len(sys.argv) > 1 else Path('build/privacy-scanner').resolve()


class ScannerTests(unittest.TestCase):
    def check_parts(self, parts):
        original = ''
        sanitized = ''
        findings = []
        for text, kind in parts:
            if kind:
                prefix = original.rsplit('\n', 1)[-1]
                findings.append({'type': kind, 'line': original.count('\n') + 1,
                                 'column': len(prefix) + 1, 'length': len(text)})
                sanitized += '[' + kind + ']'
            else:
                sanitized += text
            original += text
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            source = work / 'input.data'
            source.write_bytes(original.encode('utf-8'))
            result = subprocess.run([str(SCANNER), str(source)], cwd=work, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))
            self.assertEqual(source.read_bytes(), original.encode('utf-8'))
            self.assertEqual({p.name for p in work.iterdir()}, {'input.data', 'sanitized.txt', 'report.json'})
            self.assertEqual((work / 'sanitized.txt').read_bytes(), sanitized.encode('utf-8'))
            report = json.loads((work / 'report.json').read_bytes())
            self.assertEqual(report, {'total_detected': len(findings), 'findings': findings})
            self.assertIs(type(report['total_detected']), int)
            for finding in report['findings']:
                self.assertIs(type(finding['type']), str)
                for key in ('line', 'column', 'length'):
                    self.assertIs(type(finding[key]), int)

    def check_candidates(self, candidates):
        parts = []
        for text, kind in candidates:
            parts.extend([(text, kind), (' ; ', None)])
        self.check_parts(parts)

    def test_assignment_intro(self):
        self.check_parts([('User ', None), ('ali@example.com', 'EMAIL'),
                          (' reported an error.\nHis phone number is ', None),
                          ('09123456789', 'PHONE'),
                          ('.\nThe request came from ', None), ('192.168.1.15', 'IP'), ('.\n', None)])

    def test_assignment_boundaries_and_trailing_dots(self):
        self.check_parts([('Contact ', None), ('ali@example.com', 'EMAIL'), (', call ', None),
                          ('09123456789', 'PHONE'), ('!\nContact ', None),
                          ('ali@example.com', 'EMAIL'), ('.\nIP address is ', None),
                          ('192.168.1.15', 'IP'), ('.\n', None),
                          ('abc09123456789 999.168.1.15 ali..reza@example.com 192.168.1.15.30\n', None),
                          ('a@b.co', 'EMAIL'), ('... ', None), ('1.2.3.4', 'IP'),
                          ('.... ', None), ('09123456789', 'PHONE'), ('..\n', None)])

    def test_assignment_json_example_positions(self):
        self.check_parts([('Contact ', None), ('ali@example.com', 'EMAIL'), (' from ', None),
                          ('192.168.1.15', 'IP'), ('\nPhone: ', None), ('09123456789', 'PHONE')])

    def test_valid_emails(self):
        self.check_candidates([(s, 'EMAIL') for s in (
            'z@q.ir', 'M7@Example.COM', 'r.s@b.co', 'a_-b@one-two.net',
            '1@2.co', 'a.b-c_d.9@sub-7.host.co', 'q--__x@d.io',
            'first.last@a.b.c.d.EF', 'a@0.co', 'a' * 10000 + '@host.example')])

    def test_invalid_emails(self):
        self.check_candidates([(s, None) for s in (
            '@host.co', 'abc@', 'a@@host.co', '.a@host.co', '_a@host.co', '-a@host.co',
            'a_@host.co', 'a-@host.co', 'a..b@host.co', 'a._b@host.co', 'a-.b@host.co',
            'a._.b@host.co', 'a@host', 'a@host.c', 'a@host.12', 'a@host.c2',
            'a@host.2c', 'a@host.c-o', 'a@host.c_o', 'a@-host.co', 'a@host-.co',
            'a@ho_st.co', 'a@.host.co', 'a@host..co', 'a@host.co_',
            'a@host.co-', 'a@host.co@x', 'a@host.co.0', 'a@host..co...')])

    def test_phone_shapes(self):
        self.check_candidates([(s, 'PHONE') for s in ('09000000000', '09123456789', '09999999999')])
        invalid = ['', '09', '09123-456789', '0912_3456789', '0912.3456789',
                   '989123456789', '00989123456789', '08123456789', '19123456789',
                   'a09123456789', '09123456789a', '_09123456789', '.09123456789',
                   '09123456789@', '09123456789_']
        invalid.extend('09' + '7' * n for n in range(20) if n != 9)
        self.check_candidates([(s, None) for s in invalid])

    def test_phone_separators(self):
        self.check_parts([('(+98) 9123456789 0912 345 6789 (0912)3456789 +989123456789\n(', None),
                          ('09123456789', 'PHONE'), (') / +', None), ('09123456789', 'PHONE'),
                          (' / سلام', None), ('09123456789', 'PHONE'), ('پایان', None)])

    def test_ipv4_octet_boundaries(self):
        candidates = []
        for slot in range(4):
            for value in (0, 1, 9, 10, 99, 100, 199, 200, 249, 250, 254, 255, 256, 999, 1000):
                octets = ['7', '8', '9', '10']
                octets[slot] = str(value)
                candidates.append(('.'.join(octets), 'IP' if value <= 255 else None))
            for value in ('00', '01', '001', '09', '010', '0000'):
                octets = ['7', '8', '9', '10']
                octets[slot] = value
                candidates.append(('.'.join(octets), None))
        candidates.extend([(s, 'IP') for s in ('0.0.0.0', '255.255.255.255', '127.0.0.1')])
        self.check_candidates(candidates)

    def test_invalid_ipv4_candidates(self):
        self.check_candidates([(s, None) for s in (
            '1.2.3', '1.2', '1', '1.2.3.4.5', '.1.2.3.4', '1..2.3.4',
            '1.2..3.4', '1.2.3.-4', '-1.2.3.4', '_1.2.3.4', 'x1.2.3.4',
            '1.2.3.4x', '1.2.3.4_', '1.2.3.4@', '0x1.2.3.4',
            '1.2.3.9999999999999999999999999999', '999.168.1.15')])

    def test_whole_candidate_and_no_rescanning(self):
        self.check_parts([('.user@host.co _user@host.co user@host.co_ user@host.co@other.net ', None),
                          ('09123456789.1.2.3.4 1.2.3.4.09123456789 a@host.co-09123456789 ', None),
                          ('[EMAIL] [PHONE] [IP] ', None), ('user@host.co', 'EMAIL'),
                          (' ', None), ('user@host.co', 'EMAIL'), ('\n', None),
                          ('09123456789', 'PHONE'), (' ', None), ('09123456789', 'PHONE')])

    def test_unicode_columns_and_original_offsets(self):
        self.check_parts([('\ufeffسلام🙂e\u0301\t', None), ('z@q.ir', 'EMAIL'), (' ', None),
                          ('09123456789', 'PHONE'), ('،\r\nمتن\t', None), ('1.2.3.4', 'IP'),
                          ('\r', None), ('a@b.co', 'EMAIL'), ('\n\r\r\n', None),
                          ('09999999999', 'PHONE'), ('\x00\t\U0010ffff', None), ('255.0.2.9', 'IP')])

    def test_non_ascii_digits_are_separators(self):
        self.check_parts([('۰۹۱۲۳۴۵۶۷۸۹ ٠٩١٢٣٤٥٦٧٨٩ ۱۹۲.۱۶۸.۱.۱۵\n', None),
                          ('۱', None), ('09123456789', 'PHONE'), ('۲\n', None),
                          ('１', None), ('1.2.3.4', 'IP'), ('۹', None)])

    def test_no_findings_preserves_every_byte(self):
        for source in ('', '\ufeff', '... . @ _ -', '\t\n\r\n\r\r\n',
                       'فارسی🙂\x00\t۰۹۱۲۳۴۵۶۷۸۹\r\nplain words and 999.1.2.3.',
                       'x' * 100000 + '09123456789'):
            with self.subTest(source=source[:50]):
                self.check_parts([(source, None)])

    def test_missing_input_and_usage(self):
        with tempfile.TemporaryDirectory() as tmp:
            for arguments in ([], ['missing.txt'], ['one', 'two']):
                result = subprocess.run([str(SCANNER), *arguments], cwd=tmp, capture_output=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertTrue(result.stderr)
                self.assertEqual(list(Path(tmp).iterdir()), [])

    def test_rejects_malformed_utf8_before_outputs(self):
        invalid = [b'\x80', b'\xc0\x80', b'\xed\xa0\x80', b'\xf4\x90\x80\x80',
                   b'\xe2\x82', b'\xf0\x80\x80\x80', b'\xff', b'\xe2x\xa1']
        for data in invalid:
            with self.subTest(data=data), tempfile.TemporaryDirectory() as tmp:
                source = Path(tmp) / 'bad.txt'
                source.write_bytes(b'09123456789 ' + data)
                result = subprocess.run([str(SCANNER), str(source)], cwd=tmp, capture_output=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual({p.name for p in Path(tmp).iterdir()}, {'bad.txt'})
                self.assertEqual(source.read_bytes(), b'09123456789 ' + data)

    def test_output_paths_cannot_alias(self):
        for alias in ('symlink', 'dangling_symlink', 'hardlink'):
            with self.subTest(alias=alias), tempfile.TemporaryDirectory() as tmp:
                work = Path(tmp)
                source = work / 'input.txt'
                source.write_bytes(b'09123456789')
                report = work / 'report.json'
                if alias != 'dangling_symlink':
                    report.write_bytes(b'existing output')
                sanitized = work / 'sanitized.txt'
                if alias == 'hardlink':
                    sanitized.hardlink_to(report)
                else:
                    sanitized.symlink_to(report)
                result = subprocess.run([str(SCANNER), str(source)], cwd=work, capture_output=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(source.read_bytes(), b'09123456789')
                if alias != 'dangling_symlink':
                    self.assertEqual(report.read_bytes(), b'existing output')
                else:
                    self.assertFalse(report.exists())

    def test_input_cannot_alias_an_output(self):
        for output in ('sanitized.txt', 'report.json'):
            for alias in ('same', 'symlink', 'hardlink'):
                with self.subTest(output=output, alias=alias), tempfile.TemporaryDirectory() as tmp:
                    work = Path(tmp)
                    source = work / ('input.txt' if alias != 'same' else output)
                    data = b'secret: 09123456789\n'
                    source.write_bytes(data)
                    target = work / output
                    if alias == 'symlink':
                        target.symlink_to(source)
                    elif alias == 'hardlink':
                        target.hardlink_to(source)
                    result = subprocess.run([str(SCANNER), str(source)], cwd=work, capture_output=True)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(source.read_bytes(), data)


if __name__ == '__main__':
    unittest.main()
