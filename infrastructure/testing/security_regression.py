#!/usr/bin/env python3
"""Offline-first security regression. Never invokes Docker or live acceptance."""
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[2]
JAVA_TESTS = (
    'HumanJwtSecurityChainTest', 'MachineSecurityTest',
    'MachineSecurityChainTest', 'MachineCertificateBindingTest', 'MachineTlsTest',
    'AuthorizationServiceTest', 'ResourceRepositoryTest', 'ResourceEndpointsTest',
    'OpenFgaClientTest', 'OpaClientTest',
)
PYTHON_TESTS = (
    ('infrastructure/docker', 'test_machine_keycloak'),
    ('infrastructure/docker/pki', 'test_generate'),
    ('authorization/openfga', 'test_deploy'),
    ('authorization/openfga', 'test_fixtures'),
)
SENSITIVE = re.compile(
    r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'
    r'|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'
    r'|test-only-password|unchanged-test-secret|test-secret-token|user:password'
)


class Failure(Exception):
    pass


def capture(command, cwd, env, timeout=300):
    try:
        return subprocess.run(command, cwd=cwd, env=env, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, text=True, timeout=timeout)
    except FileNotFoundError:
        raise Failure('required executable missing') from None
    except subprocess.TimeoutExpired:
        raise Failure('command timed out; raw output suppressed') from None


def checked(command, cwd, env, label):
    result = capture(command, cwd, env)
    if SENSITIVE.search(result.stdout):
        raise Failure(label + ': sensitive test output detected and suppressed')
    if result.returncode:
        raise Failure(label + ': command failed; raw output suppressed')
    return result.stdout


def java_home(env):
    configured = os.environ.get('JAVA21_HOME') or os.environ.get('JAVA_HOME')
    if configured:
        home = Path(configured)
    elif sys.platform == 'darwin':
        result = capture(['/usr/libexec/java_home', '-v', '21'], ROOT, env)
        if result.returncode:
            raise Failure('Java 21 missing: set JAVA21_HOME to a JDK 21 installation')
        home = Path(result.stdout.strip())
    else:
        java = shutil.which('java')
        if not java:
            raise Failure('Java 21 missing: set JAVA21_HOME')
        home = Path(java).resolve().parent.parent
    if not all((home / 'bin' / name).is_file() for name in ('java', 'javac', 'keytool')):
        raise Failure('JAVA21_HOME/JAVA_HOME must identify a full JDK 21')
    version = capture([str(home / 'bin/java'), '-version'], ROOT, env)
    if version.returncode or not re.search(r'version "21(?:\.|\")', version.stdout):
        raise Failure('Java 21 required; set JAVA21_HOME (no fallback to another major version)')
    return home


def java_suite(work, env, mvn):
    api = work / 'api'
    api.mkdir()
    shutil.copyfile(ROOT / 'apps/api/pom.xml', api / 'pom.xml')
    shutil.copytree(ROOT / 'apps/api/src', api / 'src')
    resources = api / 'src/test/resources'
    resources.mkdir(parents=True, exist_ok=True)
    logback = resources / 'logback-test.xml'
    # Existing client tests assert sanitized WARN output; audit tests attach their
    # own in-memory appender. Do not enable framework request/JWT DEBUG logging.
    logback.write_text('''<configuration>
      <appender name="SANITIZED" class="ch.qos.logback.core.ConsoleAppender">
        <encoder><pattern>%msg%n</pattern></encoder>
      </appender>
      <logger name="dev.portfolio.iam.authorization.OpaClient" level="WARN" additivity="false">
        <appender-ref ref="SANITIZED"/>
      </logger>
      <logger name="dev.portfolio.iam.authorization.OpenFgaClient" level="WARN" additivity="false">
        <appender-ref ref="SANITIZED"/>
      </logger>
      <root level="INFO"/>
    </configuration>\n''')
    jul = work / 'logging.properties'
    jul.write_text('.level=OFF\n')
    settings = work / 'settings.xml'
    settings.write_text('<settings xmlns="http://maven.apache.org/SETTINGS/1.0.0"/>\n')
    args = (f'-Dlogback.configurationFile={logback.as_uri()} '
            f'-Dlogging.config={logback.as_uri()} '
            f'-Djava.util.logging.config.file={jul} -Dspring.main.banner-mode=off')
    result = capture([mvn, '-o', '-B', '-q', '-s', str(settings), '-gs', str(settings),
                      '-Dtest=' + ','.join(JAVA_TESTS), '-DfailIfNoTests=true',
                      '-DargLine=' + args, 'test'], api, env)
    reports = list((api / 'target/surefire-reports').glob('TEST-*.xml'))
    if SENSITIVE.search(result.stdout) or any(SENSITIVE.search(p.read_text()) for p in reports):
        raise Failure('Java: sensitive test output detected; temporary reports will be deleted')
    if result.returncode:
        raise Failure('Java: Maven failed (check cached dependencies, Java 21 and socket permissions); raw output suppressed')
    suites = [ET.parse(p).getroot() for p in reports]
    if {s.attrib['name'].rsplit('.', 1)[-1] for s in suites} != set(JAVA_TESTS):
        raise Failure('Java: selected suite report set mismatch')
    totals = {key: sum(int(s.attrib.get(key, 0)) for s in suites)
              for key in ('tests', 'failures', 'errors', 'skipped')}
    if not totals['tests'] or any(totals[k] for k in ('failures', 'errors', 'skipped')):
        raise Failure('Java: failed, empty or skipped selected tests')
    print(f"PASS Java: {totals['tests']} tests; 0 failures/errors/skips", flush=True)


def python_suites(env):
    # Deny external effects even if a selected mock-based test drifts later.
    harness = '''import sys, unittest
def guard(event, args):
    if event in ('socket.connect', 'socket.bind', 'subprocess.Popen', 'os.system'):
        raise RuntimeError('Offline test forbids external operations')
sys.addaudithook(guard)
suite = unittest.defaultTestLoader.loadTestsFromName(sys.argv[1])
result = unittest.TextTestRunner(verbosity=0).run(suite)
if not result.wasSuccessful() or result.skipped or result.testsRun == 0:
    sys.exit(1)
print('COUNT=' + str(result.testsRun))
'''
    total = 0
    for directory, module in PYTHON_TESTS:
        output = checked([sys.executable, '-B', '-c', harness, module],
                         ROOT / directory, env, 'Python ' + module)
        match = re.search(r'^COUNT=(\d+)$', output, re.M)
        if not match:
            raise Failure('Python: missing test count')
        count = int(match.group(1))
        total += count
        print(f'PASS Python {module}: {count} tests', flush=True)
    print(f'PASS Python total: {total} tests; 0 failures/errors/skips', flush=True)


def optional_checks(env, work):
    # Fresh HOME and allowlisted environment prevent inherited CLI credentials/config.
    optional_env = dict(env, HOME=str(work))
    for tool, commands, directory in (
        ('opa', [('check', '--strict', 'policies', 'tests'),
                 ('test', 'policies', 'tests')], 'authorization/opa'),
        ('fga', [('model', 'validate', '--file', 'model.fga'),
                 ('model', 'test', '--tests', 'model.fga.yaml')], 'authorization/openfga'),
    ):
        executable = shutil.which(tool, path=env['PATH'])
        if not executable:
            print(f'SKIP {tool}: optional native executable unavailable; no Docker fallback', flush=True)
            continue
        for command in commands:
            checked([executable, *command], ROOT / directory, optional_env, tool)
        print(f'PASS {tool}: local model/policy checks', flush=True)


def main():
    # No inherited IAM credentials, integration triggers, proxy variables or JVM options.
    env = {'PATH': os.environ.get('PATH', os.defpath), 'HOME': str(Path.home()),
           'LANG': 'C', 'PYTHONDONTWRITEBYTECODE': '1'}
    mvn = shutil.which('mvn', path=env['PATH'])
    if not mvn:
        raise Failure('Maven missing: install mvn and pre-cache project dependencies')
    home = java_home(env)
    env.update(JAVA_HOME=str(home), PATH=str(home / 'bin') + os.pathsep + env['PATH'],
               MAVEN_SKIP_RC='true')
    print('PASS prerequisites: JDK 21 and Maven; offline dependency resolution', flush=True)
    with tempfile.TemporaryDirectory(prefix='iam-security-regression-') as directory:
        work = Path(directory)
        env['TMPDIR'] = str(work)
        java_suite(work, env, mvn)
        python_suites(env)
        optional_checks(env, work)
    print('PASS offline security regression; not live deployment acceptance', flush=True)


if __name__ == '__main__':
    try:
        main()
    except Failure as error:
        print('FAIL ' + str(error), file=sys.stderr)
        sys.exit(1)
    except Exception:
        print('FAIL runner error; raw exception suppressed', file=sys.stderr)
        sys.exit(1)
