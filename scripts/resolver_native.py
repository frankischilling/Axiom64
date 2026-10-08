"""Check resolver file/ownership contracts on native Linux with sanitizers."""
import json
import platform
import subprocess
from fetch import ROOT
from resolver_test import MARKERS


def main():
    log = ROOT / 'build/resolver-native.log'
    timed_out = False
    with log.open('wb') as output:
        process = subprocess.Popen([str(ROOT / 'build/resolver-native'), '--native'],
                                   cwd=ROOT, stdout=output, stderr=subprocess.STDOUT,
                                   stdin=subprocess.DEVNULL)
        try:
            process.wait(timeout=30)
        except subprocess.TimeoutExpired:
            timed_out = True
            process.kill()
            process.wait()
    text = log.read_text(errors='replace')
    missing = [marker for marker in MARKERS if marker not in text]
    result = dict(kernel=platform.release(), returncode=process.returncode,
                  timed_out=timed_out, missing=missing, log=log.name,
                  passed=not timed_out and process.returncode == 0 and not missing and
                  'ERROR: AddressSanitizer' not in text and 'runtime error:' not in text)
    (ROOT / 'build/resolver-native-results.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result), flush=True)
    if not result['passed']:
        print(text[-2500:], flush=True)
        raise SystemExit('Native resolver contracts failed')


if __name__ == '__main__':
    main()
