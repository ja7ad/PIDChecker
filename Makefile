# PID Key Checker: build, package and end-to-end test helpers.
#
#   make dist            Windows ARM64 + x64 packages in target/dist/
#   make dist-arm64      only ARM64 (target/dist/pidkeychecker-<ver>-win-arm64[.zip])
#   make vm-deploy       copy the ARM64 package into the Parallels VM
#   make vm-test         smoke-test pkc.exe inside the VM
#   make e2e             dist-arm64 + vm-deploy + vm-test
#
# Cross-compiling needs cargo-xwin (cargo install cargo-xwin) and the Rust
# targets: rustup target add aarch64-pc-windows-msvc x86_64-pc-windows-msvc

VERSION   := $(shell sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
DIST      := target/dist
ARM64     := aarch64-pc-windows-msvc
X64       := x86_64-pc-windows-msvc
CARGO_WIN ?= cargo xwin

# Parallels VM used for end-to-end tests.
VM        ?= Windows 11
VM_DIR    ?= C:\pkc-e2e
VM_SHARE  ?= \\Mac\Home$(subst /,\,$(patsubst $(HOME)%,%,$(CURDIR)))

.PHONY: all help test lint build dist dist-arm64 dist-x64 vm-deploy vm-test vm-gui e2e clean-dist

all: dist

help:
	@sed -n 's/^#   //p' Makefile

test:
	cargo test --release

lint:
	cargo clippy --release --all-targets -- -D warnings

build:
	cargo build --release

dist: dist-arm64 dist-x64

dist-arm64:
	$(CARGO_WIN) build --release --target $(ARM64)
	@$(MAKE) --no-print-directory package TRIPLE=$(ARM64) NAME=win-arm64 WITH_PIDGENX=1

# The bundled pidgenx.dll is ARM64-only; x64 builds use %WINDIR%\System32\pidgenx.dll.
dist-x64:
	$(CARGO_WIN) build --release --target $(X64)
	@$(MAKE) --no-print-directory package TRIPLE=$(X64) NAME=win-x64 WITH_PIDGENX=0

# Internal: assemble target/dist/pidkeychecker-<version>-<NAME>/ and zip it.
package:
	$(eval OUT := $(DIST)/pidkeychecker-$(VERSION)-$(NAME))
	rm -rf "$(OUT)" "$(OUT).zip"
	mkdir -p "$(OUT)"
	cp target/$(TRIPLE)/release/pidkeychecker.exe target/$(TRIPLE)/release/pkc.exe "$(OUT)/"
	cp -R data "$(OUT)/data"
	cp README.md "$(OUT)/"
	@if [ "$(WITH_PIDGENX)" = "1" ] && [ -f pidgenx.dll ]; then cp pidgenx.dll "$(OUT)/"; fi
	printf '# PID Key Checker configuration\n\n[server]\nhost = "127.0.0.1"\nport = 8080\n\n[checker]\ndata_dir = "data"\npidgenx_path = "pidgenx.dll"\n' > "$(OUT)/config.toml"
	cd "$(DIST)" && zip -qr "pidkeychecker-$(VERSION)-$(NAME).zip" "pidkeychecker-$(VERSION)-$(NAME)"
	@echo "packaged $(OUT) and $(OUT).zip"

# Copy the ARM64 package into the VM (replaces $(VM_DIR); close the app there first).
vm-deploy:
	prlctl exec "$(VM)" powershell -NoProfile -Command \
		"Get-Process pidkeychecker,pkc -EA SilentlyContinue | Where-Object { $$_.Path -like '$(VM_DIR)*' } | Stop-Process -Force; \
		 if (Test-Path '$(VM_DIR)') { Remove-Item '$(VM_DIR)' -Recurse -Force }; \
		 Copy-Item '$(VM_SHARE)\target\dist\pidkeychecker-$(VERSION)-win-arm64' '$(VM_DIR)' -Recurse; \
		 Get-ChildItem '$(VM_DIR)' -Name"

# Non-interactive smoke test of the deployed package inside the VM.
vm-test:
	prlctl exec "$(VM)" powershell -NoProfile -Command \
		"Set-Location '$(VM_DIR)'; \
		 .\pkc.exe --version; \
		 .\pkc.exe config path; \
		 .\pkc.exe check --offline W269N-WFGWX-YVC9B-4J6C9-T83GX NPPR9-FWDCX-D2C8J-H872K-2YT43 | Select-String 'Key  |Status|Description'; \
		 .\pkc.exe blocklist count; \
		 .\pkc.exe error 0xC004C003 | Select-Object -First 2; \
		 \$$s = Start-Process .\pkc.exe -ArgumentList 'serve','--port','18090' -PassThru -WindowStyle Hidden; Start-Sleep 2; \
		 try { (Invoke-RestMethod http://127.0.0.1:18090/api/v1/health).database } finally { Stop-Process -Id \$$s.Id -Force }"

# Start the GUI in the logged-in user's session.
vm-gui:
	prlctl exec "$(VM)" --current-user powershell -NoProfile -Command \
		"Start-Process '$(VM_DIR)\pidkeychecker.exe' -WorkingDirectory '$(VM_DIR)'" &

e2e: dist-arm64 vm-deploy vm-test

clean-dist:
	rm -rf $(DIST)
