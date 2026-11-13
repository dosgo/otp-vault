"""
构建「口令宝」Android APK。
纯手工工具链：aapt2 / javac / d8 / zipalign / apksigner，不需要 Gradle，也不需要联网下载依赖。

运行：  python android/build.py
输出：  otp-vault.apk （项目根目录）
"""
import os
import pathlib
import shutil
import subprocess
import sys
import zipfile

ROOT = pathlib.Path(__file__).resolve().parent      # otp-app/android
WEB = ROOT.parent                                   # otp-app
BUILD = ROOT / 'build'
FLAT = BUILD / 'flat'
CLASSES = BUILD / 'classes'
DEX = BUILD / 'dex'
GEN = BUILD / 'gen'
ASSETS = BUILD / 'assets' / 'www'
DIST = WEB / 'otp-vault.apk'
KEYSTORE = ROOT / 'otp-vault.keystore'
KEYPASS = 'otpvault2026'

SDK = pathlib.Path(os.environ.get('ANDROID_HOME') or os.environ.get('ANDROID_SDK_ROOT')
                   or r'C:\Users\DosGo\AppData\Local\Android\Sdk')
PLATFORM = SDK / 'platforms' / 'android-34' / 'android.jar'
BT = SDK / 'build-tools' / '33.0.1'  # 34.0.0 的 d8 需要 Java 11，本机 JDK 8；33.0.1 全套兼容

WEB_FILES = [
    'index.html', 'styles.css', 'app.js', 'totp.js', 'migration.js', 'zipcrypt.js',
    'manifest.webmanifest', 'sw.js',
    'vendor/jsQR.js',
    'icons/icon-192.png', 'icons/icon-512.png', 'icons/icon-maskable-512.png',
]


def q(p):
    return '"' + str(p) + '"'


def run(cmd):
    print('> ' + cmd, flush=True)
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True,
                       encoding='utf-8', errors='replace')
    out = (r.stdout or '').strip()
    err = (r.stderr or '').strip()
    if out:
        print('\n'.join(out.splitlines()[-25:]), flush=True)
    if r.returncode != 0:
        if err:
            print('STDERR:\n' + '\n'.join(err.splitlines()[-40:]), flush=True)
        raise SystemExit(f'构建失败（退出码 {r.returncode}）')


def prepare():
    for path in (PLATFORM, BT / 'aapt2.exe', BT / 'd8.bat', BT / 'zipalign.exe', BT / 'apksigner.bat'):
        if not path.exists():
            raise SystemExit(f'缺少构建工具：{path}')
    if BUILD.exists():
        shutil.rmtree(BUILD)
    for d in (FLAT, CLASSES, DEX, GEN, ASSETS):
        d.mkdir(parents=True, exist_ok=True)
    for rel in WEB_FILES:
        src = WEB / rel
        dst = ASSETS / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
    # 启动图标：192px 正好对应 xxxhdpi
    icon_dir = ROOT / 'res' / 'mipmap-xxxhdpi'
    icon_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(WEB / 'icons' / 'icon-192.png', icon_dir / 'ic_launcher.png')
    print(f'✓ 资源准备完成（{len(WEB_FILES)} 个 Web 文件 + 启动图标）')


def main():
    prepare()
    res = ROOT / 'res'
    res_files = sorted(p for p in res.rglob('*') if p.is_file())

    # 1) 编译资源为 .flat
    for f in res_files:
        run(f'{q(BT / "aapt2.exe")} compile {q(f)} -o {q(FLAT)}')
    flats = sorted(FLAT.glob('*.flat'))
    print(f'✓ aapt2 compile：{len(flats)} 个资源')

    # 2) 链接成基础 APK（含 assets、二进制 Manifest、resources.arsc）
    run(f'{q(BT / "aapt2.exe")} link -o {q(BUILD / "base.apk")} -I {q(PLATFORM)} '
        f'--manifest {q(ROOT / "AndroidManifest.xml")} -A {q(BUILD / "assets")} '
        f'--java {q(GEN)} --min-sdk-version 24 --target-sdk-version 34 '
        + ' '.join(q(f) for f in flats))

    # 3) 编译 Java 源码
    src = ROOT / 'src' / 'com' / 'otpvault' / 'app' / 'MainActivity.java'
    run(f'javac -source 8 -target 8 -encoding UTF-8 -bootclasspath {q(PLATFORM)} '
        f'-d {q(CLASSES)} {q(src)}')
    classes = sorted(str(p) for p in CLASSES.rglob('*.class'))
    print(f'✓ javac：{len(classes)} 个 class')

    # 4) 转成 DEX
    run(f'{q(BT / "d8.bat")} --lib {q(PLATFORM)} --min-api 24 --output {q(DEX)} '
        + ' '.join(q(c) for c in classes))
    dex_file = DEX / 'classes.dex'
    if not dex_file.exists():
        raise SystemExit('未生成 classes.dex')
    print(f'✓ d8：classes.dex {dex_file.stat().st_size} bytes')

    # 5) 把 DEX 放进 APK
    with zipfile.ZipFile(BUILD / 'base.apk', 'a', zipfile.ZIP_DEFLATED) as z:
        z.write(dex_file, 'classes.dex')

    # 6) 对齐
    run(f'{q(BT / "zipalign.exe")} -f 4 {q(BUILD / "base.apk")} {q(BUILD / "aligned.apk")}')

    # 7) 生成签名密钥（首次），后续复用，保证升级安装不冲突
    if not KEYSTORE.exists():
        run(f'keytool -genkeypair -alias otpvault -keyalg RSA -keysize 2048 -validity 10950 '
            f'-keystore {q(KEYSTORE)} -storepass {KEYPASS} -keypass {KEYPASS} '
            f'-dname "CN=OTP Vault, OU=Personal, O=OTP Vault, L=CN, ST=CN, C=CN"')
        print(f'✓ 已生成签名密钥：{KEYSTORE}（请妥善保留，后续升级要用同一把）')

    # 8) 签名 + 验证
    run(f'{q(BT / "apksigner.bat")} sign --ks {q(KEYSTORE)} --ks-pass pass:{KEYPASS} '
        f'--key-pass pass:{KEYPASS} --v1-signing-enabled true --v2-signing-enabled true '
        f'--out {q(DIST)} {q(BUILD / "aligned.apk")}')
    run(f'{q(BT / "apksigner.bat")} verify --verbose {q(DIST)}')

    print('\n' + '=' * 60)
    print(f'✅ APK 构建完成：{DIST}')
    print(f'   大小：{DIST.stat().st_size / 1024 / 1024:.2f} MB')
    print(f'   包名：com.otpvault.app   最低 Android 7.0 (API 24)')
    print('=' * 60)


if __name__ == '__main__':
    main()
