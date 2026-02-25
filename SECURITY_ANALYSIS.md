# Firefox Memory Corruption Vulnerability Analysis

## Executive Summary

Comprehensive security audit of Firefox source code targeting controllable memory
corruption vulnerabilities across JIT compiler, DOM/Layout, IPDL/IPC, image/media
decoders, WebAssembly, and WebGL/Canvas shared memory paths.

**Areas analyzed:**
1. SpiderMonkey JIT (RangeAnalysis, AliasAnalysis, GVN, WarpBuilder, LICM)
2. DOM UAF via custom element callbacks, MutationObserver, event dispatch
3. IPDL/Shmem TOCTOU and parent-process IPC handler security
4. Image decoders (PNG, GIF, WebP, AVIF) integer overflows
5. WebAssembly bounds check elimination
6. WebGL/Canvas shared memory TOCTOU
7. MP4 Rust-to-C++ FFI boundary
8. Parent-process IPC handlers exploitable from compromised content

---

## FINDING 1: Non-Fatal Principal Validation in Release Builds (IPC Sandbox Weakening)

**Severity:** High (potential privilege escalation from compromised content process)
**Impact Tier:** High to Highest ($5K-$20K depending on exploitability)
**Type:** Logic error -- missing enforcement in release builds

### Location
- **File:** `dom/ipc/ContentParent.cpp`
- **Function:** `LogAndAssertFailedPrincipalValidationInfo` (lines 1265-1309)
- **Affected handlers:** 13+ IPC handlers (lines 3164, 3363, 4144, 5404, 5712, 5727, 5744, 5759, 5849, 5871, 6393, 6570, 6653)

### Root Cause

The `ValidatePrincipal()` function returns a boolean indicating whether a
principal received from a content process is valid for that process's remote
type. When validation fails, the code calls `LogAndAssertFailedPrincipalValidationInfo()`,
which:

```cpp
void ContentParent::LogAndAssertFailedPrincipalValidationInfo(
    nsIPrincipal* aPrincipal, const char* aMethod) {
  // ... telemetry and logging ...

#ifdef DEBUG
  MOZ_ASSERT(false, "Receiving unexpected Principal");
#endif
}
```

- In **DEBUG builds**: hits `MOZ_ASSERT(false)` and crashes
- In **RELEASE builds**: only logs telemetry and returns normally

After calling `LogAndAssertFailedPrincipalValidationInfo`, execution **continues
with the invalid principal** in all 13+ call sites. The pattern is:

```cpp
if (!ValidatePrincipal(aPrincipal)) {
    LogAndAssertFailedPrincipalValidationInfo(aPrincipal, __func__);
}
// Execution continues with potentially forged principal
```

None of these sites return `IPC_FAIL` or otherwise abort the operation.

### Affected Handlers

| Handler | Line | What Continues with Invalid Principal |
|---------|------|--------------------------------------|
| `RecvSetClipboard` | 3160 | Clipboard write with forged principal |
| `RecvCreateWindow` | 5403 | Window creation with forged triggering principal |
| `RecvNotifyPushObservers` | 5711 | Push notification dispatch with forged principal |
| `RecvNotifyPushObserversWithData` | 5726 | Push notification with data, forged principal |
| `RecvPushError` | 5743 | Push error dispatch with forged principal |
| `RecvNotifyPushSubscriptionModifiedObservers` | 5758 | Push subscription modification with forged principal |
| `RecvStoreAndBroadcastBlobURLRegistration` | 5848 | Blob URL registered with forged principal (AllowSystem!) |
| `RecvUnstoreAndBroadcastBlobURLUnregistration` | 5870 | Blob URL unregistration with forged principal |
| `RecvPURLClassifierConstructor` | 6392 | URL classification with forged principal |
| `RecvAutomaticStorageAccessPermissionCanBeGranted` | 6569 | Storage access decision with forged principal |
| `RecvCreateWindowInDifferentProcess` | 4144 | Cross-process window with forged principal |

### Exploitation (from compromised content process)

A compromised content process can craft IPC messages containing arbitrary
serialized principals (SystemPrincipal, ContentPrincipal for any origin, etc.).
In release builds, even when `ValidatePrincipal` correctly identifies the
principal as invalid, the operation proceeds.

Most notable: `RecvStoreAndBroadcastBlobURLRegistration` (line 5848) explicitly
passes `{ValidatePrincipalOptions::AllowSystem}`, meaning SystemPrincipal passes
validation. A compromised content process can register blob: URLs with
SystemPrincipal, which could be loaded in privileged contexts.

### Principal Forgery Mechanism

SystemPrincipal is trivially forgeable over IPC. The IPDL type definition at
`ipc/glue/PBackgroundSharedTypes.ipdlh` lines 45-46 defines `SystemPrincipalInfo`
as an empty struct. The `PrincipalInfo` union (lines 60-66) allows this variant.

Deserialization at `ipc/glue/BackgroundUtils.cpp` lines 54-55:
```cpp
case PrincipalInfo::TSystemPrincipalInfo: {
    principal = SystemPrincipal::Get();  // Creates a real SystemPrincipal
}
```

A compromised content process crafts an IPC message with the `TSystemPrincipalInfo`
discriminant. The parent deserializes it into a real `SystemPrincipal` object.

### Most Dangerous Handlers (NO AllowSystem flag)

These handlers call `ValidatePrincipal` WITHOUT `AllowSystem`, so SystemPrincipal
FAILS validation, but execution continues in release:

| Handler | Line | Impact of Forged SystemPrincipal |
|---------|------|--------------------------------|
| `RecvCreateWindow` | 4143 | Creates `WindowGlobalParent` with SystemPrincipal -- parent believes window has chrome privileges |
| `RecvNotifyPushObservers` | 5711 | Dispatches push events under arbitrary principal, can wake service workers for other origins |
| `RecvAutomaticStorageAccessPermissionCanBeGranted` | 6569 | Grants storage access permissions to arbitrary origins |
| `RecvContentBlockingUserInteraction` | 6652 | Records content blocking interactions for arbitrary origins |
| `RecvPURLClassifierConstructor` | 6392 | URL classification with forged principal |

### Exploitation Path: RecvCreateWindow

1. Compromised content process serializes `PrincipalInfo` with `TSystemPrincipalInfo`
2. Parent deserializes into real `SystemPrincipal` at `BackgroundUtils.cpp:54`
3. `ValidatePrincipal` at line 4143 returns false (no `AllowSystem`)
4. `LogAndAssertFailedPrincipalValidationInfo` logs only, returns normally in release
5. `WindowGlobalParent::CreateDisconnected(aInitialWindowInit)` at line 4190 creates
   a `WindowGlobalParent` with SystemPrincipal
6. Subsequent security checks querying this window's principal see SystemPrincipal

### Suggested Fix

Each call site should return `IPC_FAIL` when validation fails:
```cpp
if (!ValidatePrincipal(aPrincipal)) {
    LogAndAssertFailedPrincipalValidationInfo(aPrincipal, __func__);
    return IPC_FAIL(this, "Invalid principal");
}
```

---

## FINDING 2: RecvAddCertException -- Unrestricted Certificate Override from Content

**Severity:** Moderate-High (post-compromise MITM capability)
**Impact Tier:** High ($3K-$5K) -- assumes compromised content process
**Type:** Missing validation in parent-process IPC handler

### Location
- **File:** `dom/ipc/ContentParent.cpp`, lines 6545-6559
- **Function:** `ContentParent::RecvAddCertException`

### Root Cause

```cpp
mozilla::ipc::IPCResult ContentParent::RecvAddCertException(
    nsIX509Cert* aCert, const nsACString& aHostName, int32_t aPort,
    const OriginAttributes& aOriginAttributes, bool aIsTemporary,
    AddCertExceptionResolver&& aResolver) {
  nsCOMPtr<nsICertOverrideService> overrideService =
      do_GetService(NS_CERTOVERRIDE_CONTRACTID);
  if (!overrideService) {
    aResolver(NS_ERROR_FAILURE);
    return IPC_OK();
  }
  nsresult rv = overrideService->RememberValidityOverride(
      aHostName, aPort, aOriginAttributes, aCert, aIsTemporary);
  aResolver(rv);
  return IPC_OK();
}
```

No validation whatsoever:
- `aHostName` is not checked against the content process's origin
- `aPort` is not validated
- `aCert` is not validated
- No principal validation
- No rate limiting
- No user interaction required

### Exploitation

A compromised content process sends `RecvAddCertException` with:
- `aHostName = "bank.example.com"`
- `aPort = 443`
- `aCert = attacker's certificate`
- `aIsTemporary = false` (permanent override)

The parent process silently adds a permanent certificate override for the
target domain. Future HTTPS connections to that domain will accept the
attacker's certificate without warning.

### Impact

This enables MITM attacks against any website the user visits. Combined with
a content-process RCE, this is a significant post-exploitation capability.
Per Mozilla's bounty table, IPC handler bugs from a compromised content process
qualify for Highest Impact ($18K-$20K) when they constitute sandbox escape.
Certificate override manipulation enables MITM but does not directly execute
code in the parent -- it's a privilege escalation that affects the user's
security model.

### Suggested Fix

Restrict `aHostName` to the content process's origin, or require user
interaction (like the existing certificate exception dialog), or remove
this IPC endpoint entirely and handle cert exceptions only in the parent.

---

## FINDING 3: WebGPU MutableSharedMemory TOCTOU

**Severity:** Moderate-High (TOCTOU in parent process on Linux)
**Impact Tier:** Highest on Linux where WebGPU runs in parent ($18K-$20K)
**Type:** TOCTOU -- shared memory mutated between validation and use

### Location
- **File:** `dom/webgpu/ipc/WebGPUParent.cpp`, lines 1580-1617
- **File:** `gfx/wgpu_bindings/src/server.rs`, lines 2405-2425, 2676-2693

### Root Cause

`MutableSharedMemoryHandle` is used to pass buffer data from the content
process to wgpu processing. The content process retains write access to the
shared memory. The parent/GPU process reads from shmem via raw pointers
without copying the data first.

**IPDL definition** (`dom/webgpu/ipc/PWebGPU.ipdl` line 44):
```
async Messages(uint32_t nrOfMessages, ByteBuf serializedMessages,
               ByteBuf[] dataBuffers, MutableSharedMemoryHandle[] shmems);
```

**C++ mapping** (`WebGPUParent.cpp:1580-1617`):
```cpp
for (const auto& shmem : aShmems) {
    auto mapping = shmem.Map();
    auto* ptr = mapping.DataAs<uint8_t>();  // Raw pointer into shmem
    // Content process STILL HAS WRITE ACCESS to *ptr
    ffi::WGPUFfiSlice_u8 byte_slice{ptr, len};
    shmem_mappings.AppendElement(std::move(byte_slice));
}
// Raw shmem pointers passed directly to Rust wgpu
ffi::wgpu_server_messages(mContext.get(), ..., shmem_mapping_slices);
```

**Rust consumption** (`gfx/wgpu_bindings/src/server.rs:2670-2695`):
```rust
QueueWriteDataSource::Shmem(shmem_handle_index) => {
    shmem_mappings.as_slice()[shmem_handle_index].as_slice()
    // DIRECT READ FROM MUTABLE SHARED MEMORY
}
```

### Three TOCTOU Paths

1. **queue_write_buffer**: Rust calls `global.queue_write_buffer(queue_id, dst,
   offset, data)` where `data` points into mutable shmem. Content modifies data
   during `copy_nonoverlapping` in `StagingBuffer::write` (`wgpu-core/src/resource.rs:1167`).

2. **queue_write_texture**: Row-by-row copy reads from shmem multiple times.
   Content can modify data between row copies, feeding inconsistent texture data
   (especially dangerous for compressed texture formats).

3. **BufferUnmap flush** (`WebGPUParent.cpp:758-803`): `memcpy(mapped.ptr,
   src.data(), size)` where `src.data()` is in persistent shmem mapping.

### Platform Impact

- **Linux X11/Wayland** (`layers.gpu-process.enabled = false` at
  `modules/libpref/init/StaticPrefList.yaml:9753`): WebGPU runs in the
  **parent process**. TOCTOU directly affects the parent. A GPU driver
  exploit triggered through corrupted data = sandbox escape.
- **Windows/macOS/Android** (GPU process enabled): WebGPU runs in the GPU
  process. Corruption affects GPU process, not parent directly.

### Suggested Fix

Use `FreezableSharedMemoryHandle` (which creates a truly read-only mapping
the sender cannot modify) or copy data out of shmem before processing.
The comment at `ipc/glue/SharedMemoryHandle.h:155-157` warns that converting
MutableHandle to ReadOnlyHandle provides no security guarantees on the
underlying memory.

---

## FINDING 4: WebGL BigBuffer Command Queue TOCTOU

**Severity:** Medium (requires compromised content process; affects GPU process)
**Impact Tier:** High ($3K-$5K) if GPU process, Highest if parent process
**Type:** TOCTOU -- Span points directly into shared memory

### Location
- **File:** `dom/canvas/WebGLCommandQueue.h`, lines 40-56
- **File:** `dom/canvas/WebGLQueueParamTraits.h`, lines 106-121
- **File:** `dom/canvas/HostWebGLContext.h`, line 484-487
- **File:** `dom/canvas/WebGLBuffer.cpp`, line 143

### Root Cause

WebGL commands are batched into a `BigBuffer`. For buffers >64KB, BigBuffer
uses OS shared memory. When the GPU process processes commands:

1. `RangeConsumerView::ReadRange` returns pointers directly into the BigBuffer
2. `QueueParamTraits<Span<T>>::Read` creates a `Span` pointing into the BigBuffer
3. The Span is passed directly to GL functions (e.g., `gl->fBufferData`)

The data is NOT copied out of shared memory before use. Under normal operation,
the content process releases its mapping before sending the IPC message. But
a compromised content process can:
1. `dup()` the shared memory fd before the BigBuffer is sent
2. `mmap()` the duplicated fd after sending
3. Modify buffer data while the GPU process reads from it

This affects: `BufferData`, `BufferSubData`, `CompressedTexImage`, uniform
uploads, and texture data.

### Suggested Fix

Copy Span data out of shared memory into a local allocation before passing
to GL functions.

---

## FINDING 5: ipc::Shmem RevokeRights No-Op in Release Builds

**Severity:** Medium (architectural weakness)
**Type:** Missing security enforcement in release builds

### Location
- **File:** `ipc/glue/Shmem.h`, lines 147-151

### Root Cause

`Shmem::RevokeRights()` is compiled as an empty function in release builds.
The Shmem baton-passing model (sender loses access when receiver gains it)
is not enforced at the OS level in release.

A compromised content process can retain access to Shmem regions after
transferring them, enabling TOCTOU attacks on any Shmem-based IPC.

---

## FINDING 6: Canvas 2D RecordingTypes ReadVector Integer Overflow

**Severity:** Medium (potential heap buffer overflow in GPU process)
**Type:** Integer overflow leading to undersized read

### Location
- **File:** `gfx/2d/RecordingTypes.h`, lines 90-99
- **File:** `gfx/2d/RecordedEvent.h`, lines 264-267

### Root Cause

```cpp
template <class S, class T>
void ReadVector(S& aStream, std::vector<T>& aVector) {
  size_t size;
  ReadElement(aStream, size);
  if (size && aStream.good()) {
    aVector.resize(size);
    aStream.read(reinterpret_cast<char*>(aVector.data()), sizeof(T) * size);
  }
}
```

`sizeof(T) * size` is computed as `size_t` multiplication. The result is
passed to `MemReader::read(char*, std::streamsize)` where `std::streamsize`
is signed (`ssize_t`). If the product exceeds `SSIZE_MAX`, the implicit
conversion produces a negative value.

In `MemReader::read`:
```cpp
void read(char* s, std::streamsize n) {
    if (n <= (mEnd - mData)) {  // negative n <= positive delta -> TRUE
      memcpy(s, mData, n);      // n converted to size_t -> HUGE value
```

A negative `std::streamsize` passed to `memcpy` wraps to a massive `size_t`,
causing a heap buffer overflow.

### Suggested Fix

Use `CheckedInt` for `sizeof(T) * size` and validate before casting to
`std::streamsize`.

---

## Areas Found to be Well-Defended

### SpiderMonkey JIT (RangeAnalysis, AliasAnalysis, GVN, LICM)
The BCE infrastructure is sound. Range analysis uses SSA dominance correctly.
Alias analysis properly tracks `ObjectFields` for array length changes.
GVN respects dependencies. LICM checks both movability and dependency chains.
One theoretical concern: `MMinMaxArray` has a `Load` alias set but invokes
`valueOf()` -- mitigated by `setGuard()`.

### DOM UAF via Callbacks
Firefox uses a deferred execution model for JS callbacks during DOM mutations:
- Custom element reactions are queued, not invoked synchronously
- MutationObserver callbacks are microtasks
- Legacy `DOMNodeRemoved`/`DOMNodeInserted` events have been removed
- `nsAutoScriptBlocker` prevents script during critical sections
- `nsMutationGuard` detects unexpected mutations and re-validates

### Image Decoders (PNG, GIF, WebP, AVIF)
Well-protected with:
- Centralized `IsLegalSize()` with `CheckedInt32`
- Per-decoder dimension validation
- `CheckedUint32` for intermediate buffer allocations
- Pipeline clamping of frame rects

### WebAssembly Bounds Checks
Sound implementation:
- BCE relies on grow-only invariant (memory/tables can only grow)
- `memory.grow` correctly updates all cached base/bounds
- Shared memory grow is inherently safe (never moves, limit pre-set)
- Ion alias analysis correct for movable vs non-movable memories
- SIMD lane indices compile-time validated
- Table bounds dynamically checked with Spectre masking

### MP4 Rust-to-C++ FFI
Well-defended:
- `Indice` struct fields match exactly across FFI (u64/i64)
- `CheckedInteger<T>` wraps all arithmetic in `create_sample_table`
- All `as u32` casts preceded by explicit overflow checks
