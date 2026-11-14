/*
 * Torvex native core.
 *
 * Design notes
 * ------------
 * One Aho-Corasick automaton carries every case-sensitive indicator, a second
 * carries every case-insensitive indicator. Scanning is a single pass over the
 * buffer with a precomputed DFA (transitions are filled during BFS), so the
 * cost is one table lookup per byte regardless of how many patterns exist.
 *
 * The structural analysers are deliberately small, bounds-checked readers for
 * the header fields that decide exploit mitigation hygiene: W^X segments,
 * writable entry points, executable stacks, RELRO, PIE, ASLR/NX/CFG flags and
 * known packer section names. They never trust a length or an offset.
 *
 * Output is hand-written JSON. Every string is escaped; output is capped so a
 * hostile file cannot make the native layer allocate without bound.
 */

#include "torvex_core.h"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <new>
#include <string>
#include <vector>

namespace {

constexpr size_t kMaxRules = 4096;
constexpr size_t kMaxNeedlesPerRule = 64;
constexpr size_t kMaxNeedleLen = 4096;
constexpr size_t kMaxHitsPerRule = 4096;
constexpr size_t kMaxIocs = 64;
constexpr size_t kMaxStructural = 32;
constexpr size_t kEntropyWindow = 4096;
constexpr size_t kMaxScanBytes = 256u * 1024u * 1024u;

/* ------------------------------------------------------------------ JSON */

std::string json_escape(const std::string &value) {
    std::string out;
    out.reserve(value.size() + 8);
    for (unsigned char c : value) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (c < 0x20) {
                    char buffer[8];
                    std::snprintf(buffer, sizeof(buffer), "\\u%04x", c);
                    out += buffer;
                } else {
                    out += static_cast<char>(c);
                }
        }
    }
    return out;
}

/* ------------------------------------------------------------- Aho-Corasick */

struct Needle {
    int rule = -1;
    bool nocase = false;
    std::vector<unsigned char> bytes;
};

struct Rule {
    std::string id;
    bool require_all = false;
    std::vector<int> needles; /* indices into Matcher::needles */
    size_t hits = 0;
    size_t first_offset = 0;
    bool first_offset_set = false;
};

class Automaton {
  public:
    void reserve(size_t count) { nodes_.reserve(count); }

    void add(const std::vector<unsigned char> &bytes, int needle_index) {
        if (bytes.empty() || nodes_.empty()) {
            return;
        }
        int state = 0;
        for (unsigned char byte : bytes) {
            int next = nodes_[state].next[byte];
            if (next < 0) {
                next = static_cast<int>(nodes_.size());
                nodes_[state].next[byte] = next;
                nodes_.push_back(Node{});
            }
            state = next;
        }
        nodes_[state].outputs.push_back(needle_index);
    }

    void build() {
        if (nodes_.empty()) {
            return;
        }
        std::deque<int> queue;
        for (int byte = 0; byte < 256; ++byte) {
            int child = nodes_[0].next[byte];
            if (child > 0) {
                nodes_[child].fail = 0;
                queue.push_back(child);
            } else {
                nodes_[0].next[byte] = 0;
            }
        }

        while (!queue.empty()) {
            const int state = queue.front();
            queue.pop_front();
            for (int byte = 0; byte < 256; ++byte) {
                int child = nodes_[state].next[byte];
                if (child < 0) {
                    nodes_[state].next[byte] = nodes_[nodes_[state].fail].next[byte];
                    continue;
                }
                nodes_[child].fail = nodes_[nodes_[state].fail].next[byte];
                const auto &inherited = nodes_[nodes_[child].fail].outputs;
                nodes_[child].outputs.insert(nodes_[child].outputs.end(), inherited.begin(),
                                             inherited.end());
                queue.push_back(child);
            }
        }
    }

    bool empty() const { return nodes_.empty() || !has_outputs_; }

    bool has_outputs() const { return has_outputs_; }

    /* Folds the haystack to lowercase for case-insensitive rule sets. */
    void set_fold(bool fold) { fold_ = fold; }

    /* Reports (needle index, end offset) for every match. */
    template <typename Sink> void scan(const uint8_t *data, size_t len, Sink sink) const {
        if (empty() || len == 0) {
            return;
        }
        int state = 0;
        for (size_t index = 0; index < len; ++index) {
            unsigned char byte = data[index];
            if (fold_ && byte >= 'A' && byte <= 'Z') {
                byte = static_cast<unsigned char>(byte + 32);
            }
            state = nodes_[state].next[byte];
            for (int needle : nodes_[state].outputs) {
                sink(needle, index);
            }
        }
    }

  private:
    struct Node {
        Node() {
            for (int &slot : next) {
                slot = -1;
            }
        }
        int next[256];
        int fail = 0;
        std::vector<int> outputs;
    };

    std::vector<Node> nodes_{1};
    bool has_outputs_ = false;
    bool fold_ = false;

  public:
    void mark_outputs() { has_outputs_ = true; }
};

struct Matcher {
    std::vector<Needle> needles;
    std::vector<Rule> rules;
    Automaton sensitive;
    Automaton insensitive;
    bool built = false;
};

/* --------------------------------------------------------------- entropy */

double shannon_entropy(const uint8_t *data, size_t len) {
    if (len == 0) {
        return 0.0;
    }
    size_t counts[256] = {0};
    for (size_t index = 0; index < len; ++index) {
        counts[data[index]]++;
    }
    double entropy = 0.0;
    const double total = static_cast<double>(len);
    for (size_t count : counts) {
        if (count == 0) {
            continue;
        }
        const double probability = static_cast<double>(count) / total;
        entropy -= probability * (std::log2(probability));
    }
    return entropy;
}

double max_window_entropy(const uint8_t *data, size_t len) {
    if (len == 0) {
        return 0.0;
    }
    if (len <= kEntropyWindow) {
        return shannon_entropy(data, len);
    }
    double best = 0.0;
    const size_t windows = std::min<size_t>(len / kEntropyWindow, 256);
    for (size_t window = 0; window < windows; ++window) {
        best = std::max(best, shannon_entropy(data + window * kEntropyWindow, kEntropyWindow));
    }
    return best;
}

bool is_base64_char(unsigned char c) {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' ||
           c == '/' || c == '=';
}

size_t longest_base64_run(const uint8_t *data, size_t len) {
    size_t best = 0;
    size_t current = 0;
    for (size_t index = 0; index < len; ++index) {
        if (is_base64_char(data[index])) {
            current++;
            if (current > best) {
                best = current;
            }
        } else {
            current = 0;
        }
    }
    return best;
}

/* --------------------------------------------------------------- readers */

bool read_u16(const uint8_t *data, size_t len, size_t offset, bool little, uint16_t &out) {
    if (offset + 2 > len) {
        return false;
    }
    out = little ? static_cast<uint16_t>(data[offset] | (data[offset + 1] << 8))
                 : static_cast<uint16_t>((data[offset] << 8) | data[offset + 1]);
    return true;
}

bool read_u32(const uint8_t *data, size_t len, size_t offset, bool little, uint32_t &out) {
    if (offset + 4 > len) {
        return false;
    }
    if (little) {
        out = static_cast<uint32_t>(data[offset]) | (static_cast<uint32_t>(data[offset + 1]) << 8) |
              (static_cast<uint32_t>(data[offset + 2]) << 16) |
              (static_cast<uint32_t>(data[offset + 3]) << 24);
    } else {
        out = (static_cast<uint32_t>(data[offset]) << 24) |
              (static_cast<uint32_t>(data[offset + 1]) << 16) |
              (static_cast<uint32_t>(data[offset + 2]) << 8) |
              static_cast<uint32_t>(data[offset + 3]);
    }
    return true;
}

bool read_u64(const uint8_t *data, size_t len, size_t offset, bool little, uint64_t &out) {
    uint32_t low = 0;
    uint32_t high = 0;
    if (!read_u32(data, len, little ? offset : offset + 4, little, low) ||
        !read_u32(data, len, little ? offset + 4 : offset, little, high)) {
        return false;
    }
    out = little ? (static_cast<uint64_t>(high) << 32) | low
                 : (static_cast<uint64_t>(low) << 32) | high;
    return true;
}

struct Structural {
    std::string id;
    std::string detail;
};

void add_structural(std::vector<Structural> &out, const char *id, const std::string &detail) {
    if (out.size() >= kMaxStructural) {
        return;
    }
    for (const auto &existing : out) {
        if (existing.id == id) {
            return;
        }
    }
    out.push_back(Structural{id, detail});
}

/* -------------------------------------------------------------- ELF scan */

struct ImageInfo {
    std::string kind = "unknown";
    std::string arch;
    int bits = 0;
};

bool analyze_elf(const uint8_t *data, size_t len, ImageInfo &info, std::vector<Structural> &out) {
    if (len < 52 || data[0] != 0x7F || data[1] != 'E' || data[2] != 'L' || data[3] != 'F') {
        return false;
    }
    const int elf_class = data[4];
    const bool little = data[5] != 2;
    if (elf_class != 1 && elf_class != 2) {
        return false;
    }
    info.bits = elf_class == 2 ? 64 : 32;
    info.kind = elf_class == 2 ? "elf64" : "elf32";

    uint16_t type = 0;
    uint16_t machine = 0;
    if (!read_u16(data, len, 16, little, type) || !read_u16(data, len, 18, little, machine)) {
        return true;
    }
    switch (machine) {
        case 0x3E: info.arch = "x86_64"; break;
        case 0x03: info.arch = "x86"; break;
        case 0xB7: info.arch = "aarch64"; break;
        case 0x28: info.arch = "arm"; break;
        case 0xF3: info.arch = "riscv"; break;
        case 0x15: info.arch = "ppc64"; break;
        default: info.arch = "unknown"; break;
    }

    if (type == 2) {
        add_structural(out, "TVX-STRUCT-ELF-NO-PIE",
                       "ELF type ET_EXEC: the binary is not position independent");
    }

    uint64_t entry = 0;
    uint64_t phoff = 0;
    uint16_t phentsize = 0;
    uint16_t phnum = 0;
    uint64_t shoff = 0;
    uint16_t shentsize = 0;
    uint16_t shnum = 0;

    if (elf_class == 2) {
        read_u64(data, len, 24, little, entry);
        read_u64(data, len, 32, little, phoff);
        read_u16(data, len, 54, little, phentsize);
        read_u16(data, len, 56, little, phnum);
        read_u64(data, len, 40, little, shoff);
        read_u16(data, len, 58, little, shentsize);
        read_u16(data, len, 60, little, shnum);
    } else {
        uint32_t entry32 = 0;
        uint32_t phoff32 = 0;
        uint32_t shoff32 = 0;
        read_u32(data, len, 24, little, entry32);
        read_u32(data, len, 28, little, phoff32);
        read_u16(data, len, 42, little, phentsize);
        read_u16(data, len, 44, little, phnum);
        read_u32(data, len, 32, little, shoff32);
        read_u16(data, len, 46, little, shentsize);
        read_u16(data, len, 48, little, shnum);
        entry = entry32;
        phoff = phoff32;
        shoff = shoff32;
    }

    if (phentsize == 0 || phnum > 512) {
        return true;
    }

    bool has_relro = false;
    bool has_gnu_stack = false;
    int load_index = 0;

    for (uint16_t index = 0; index < phnum; ++index) {
        const size_t base = static_cast<size_t>(phoff) + static_cast<size_t>(index) * phentsize;
        if (base + 4 > len) {
            break;
        }
        uint32_t p_type = 0;
        uint32_t p_flags = 0;
        if (!read_u32(data, len, base, little, p_type)) {
            break;
        }
        if (elf_class == 2) {
            read_u32(data, len, base + 4, little, p_flags);
        } else {
            read_u32(data, len, base + 24, little, p_flags);
        }

        constexpr uint32_t kPfX = 1;
        constexpr uint32_t kPfW = 2;
        constexpr uint32_t kPtLoad = 1;
        constexpr uint32_t kPtGnuStack = 0x6474E551;
        constexpr uint32_t kPtGnuRelro = 0x6474E552;

        if (p_type == kPtGnuRelro) {
            has_relro = true;
        } else if (p_type == kPtGnuStack) {
            has_gnu_stack = true;
            if ((p_flags & kPfX) != 0) {
                add_structural(out, "TVX-STRUCT-ELF-EXEC-STACK",
                               "PT_GNU_STACK requests an executable stack");
            }
        } else if (p_type == kPtLoad) {
            load_index++;
            uint64_t vaddr = 0;
            uint64_t memsz = 0;
            if (elf_class == 2) {
                read_u64(data, len, base + 16, little, vaddr);
                read_u64(data, len, base + 40, little, memsz);
            } else {
                uint32_t vaddr32 = 0;
                uint32_t memsz32 = 0;
                read_u32(data, len, base + 8, little, vaddr32);
                read_u32(data, len, base + 20, little, memsz32);
                vaddr = vaddr32;
                memsz = memsz32;
            }
            if ((p_flags & kPfW) != 0 && (p_flags & kPfX) != 0) {
                add_structural(out, "TVX-STRUCT-ELF-WX",
                               "loadable segment " + std::to_string(load_index) +
                                   " is writable and executable (W^X violation)");
            }
            if ((p_flags & kPfW) != 0 && entry >= vaddr && entry < vaddr + memsz &&
                memsz > 0) {
                add_structural(out, "TVX-STRUCT-ELF-ENTRY-WRITABLE",
                               "entry point falls inside a writable segment");
            }
        }
    }

    if (!has_gnu_stack) {
        add_structural(out, "TVX-STRUCT-ELF-NO-GNU-STACK",
                       "no PT_GNU_STACK header: stack executability is left to the loader");
    }
    if (!has_relro) {
        add_structural(out, "TVX-STRUCT-ELF-NO-RELRO",
                       "no PT_GNU_RELRO segment: GOT entries stay writable after relocation");
    }

    /* Writable + executable sections are a strong packing/unpacking hint. */
    if (shentsize >= 40 && shnum <= 4096 && shoff != 0) {
        for (uint16_t index = 0; index < shnum; ++index) {
            const size_t base = static_cast<size_t>(shoff) + static_cast<size_t>(index) * shentsize;
            if (base + 40 > len) {
                break;
            }
            uint64_t flags = 0;
            if (elf_class == 2) {
                read_u64(data, len, base + 8, little, flags);
            } else {
                uint32_t flags32 = 0;
                read_u32(data, len, base + 8, little, flags32);
                flags = flags32;
            }
            if ((flags & 0x1) != 0 && (flags & 0x4) != 0) {
                add_structural(out, "TVX-STRUCT-ELF-WX-SECTION",
                               "section " + std::to_string(index) +
                                   " is both SHF_WRITE and SHF_EXECINSTR");
                break;
            }
        }
    }

    return true;
}

/* --------------------------------------------------------------- PE scan */

std::string section_name(const uint8_t *data, size_t offset) {
    char name[9] = {0};
    for (int index = 0; index < 8; ++index) {
        name[index] = static_cast<char>(data[offset + index]);
    }
    return std::string(name);
}

bool analyze_pe(const uint8_t *data, size_t len, ImageInfo &info, std::vector<Structural> &out) {
    if (len < 0x40 || data[0] != 'M' || data[1] != 'Z') {
        return false;
    }
    uint32_t pe_offset = 0;
    if (!read_u32(data, len, 0x3C, true, pe_offset) || pe_offset + 24 > len) {
        return false;
    }
    if (std::memcmp(data + pe_offset, "PE\0\0", 4) != 0) {
        return false;
    }

    const size_t coff = pe_offset + 4;
    uint16_t machine = 0;
    uint16_t section_count = 0;
    uint16_t optional_size = 0;
    uint16_t characteristics = 0;
    read_u16(data, len, coff, true, machine);
    read_u16(data, len, coff + 2, true, section_count);
    read_u16(data, len, coff + 16, true, optional_size);
    read_u16(data, len, coff + 18, true, characteristics);

    switch (machine) {
        case 0x8664: info.arch = "x86_64"; break;
        case 0x14C: info.arch = "x86"; break;
        case 0xAA64: info.arch = "aarch64"; break;
        default: info.arch = "unknown"; break;
    }
    info.kind = "pe";
    info.bits = machine == 0x8664 || machine == 0xAA64 ? 64 : 32;

    const size_t optional = coff + 20;
    uint16_t magic = 0;
    if (read_u16(data, len, optional, true, magic)) {
        info.kind = magic == 0x20B ? "pe32+" : "pe32";
        uint16_t dll_characteristics = 0;
        if (read_u16(data, len, optional + 70, true, dll_characteristics)) {
            constexpr uint16_t kDynamicBase = 0x0040;
            constexpr uint16_t kNxCompat = 0x0100;
            constexpr uint16_t kGuardCf = 0x4000;
            if ((dll_characteristics & kDynamicBase) == 0) {
                add_structural(out, "TVX-STRUCT-PE-NO-ASLR",
                               "DllCharacteristics has no DYNAMICBASE: ASLR is not requested");
            }
            if ((dll_characteristics & kNxCompat) == 0) {
                add_structural(out, "TVX-STRUCT-PE-NO-NX",
                               "DllCharacteristics has no NX_COMPAT: DEP is not requested");
            }
            if ((dll_characteristics & kGuardCf) == 0) {
                add_structural(out, "TVX-STRUCT-PE-NO-CFG",
                               "Control Flow Guard is not enabled");
            }
        }
    }
    if ((characteristics & 0x0001) != 0) {
        add_structural(out, "TVX-STRUCT-PE-RELOCS-STRIPPED",
                       "IMAGE_FILE_RELOCS_STRIPPED: the image cannot be rebased");
    }

    const size_t sections = optional + optional_size;
    if (sections > len || section_count > 512) {
        return true;
    }
    for (uint16_t index = 0; index < section_count; ++index) {
        const size_t base = sections + static_cast<size_t>(index) * 40;
        if (base + 40 > len) {
            break;
        }
        const std::string name = section_name(data, base);
        uint32_t raw_size = 0;
        uint32_t raw_pointer = 0;
        uint32_t section_flags = 0;
        read_u32(data, len, base + 16, true, raw_size);
        read_u32(data, len, base + 20, true, raw_pointer);
        read_u32(data, len, base + 36, true, section_flags);

        constexpr uint32_t kMemExecute = 0x20000000;
        constexpr uint32_t kMemWrite = 0x80000000;
        if ((section_flags & kMemExecute) != 0 && (section_flags & kMemWrite) != 0) {
            add_structural(out, "TVX-STRUCT-PE-RWX",
                           "section " + name + " is writable and executable");
        }

        static const char *kPackerNames[] = {"UPX0", "UPX1", "UPX2", ".aspack", ".adata",
                                             ".themida", ".vmp0", ".vmp1", ".nsp0", ".nsp1",
                                             ".packed", "pebundle", ".MPRESS1", ".MPRESS2"};
        for (const char *packer : kPackerNames) {
            if (name == packer) {
                add_structural(out, "TVX-STRUCT-PE-PACKER",
                               "packer section name present: " + name);
            }
        }

        if (raw_size >= 4096 && raw_pointer > 0 &&
            static_cast<size_t>(raw_pointer) + raw_size <= len) {
            const double entropy = shannon_entropy(data + raw_pointer, raw_size);
            if (entropy >= 7.2) {
                char buffer[96];
                std::snprintf(buffer, sizeof(buffer),
                              "section %s has entropy %.2f/8 (packed or encrypted)",
                              name.c_str(), entropy);
                add_structural(out, "TVX-STRUCT-PE-HIGH-ENTROPY-SECTION", buffer);
            }
        }
    }

    return true;
}

bool analyze_macho(const uint8_t *data, size_t len, ImageInfo &info,
                   std::vector<Structural> &out) {
    if (len < 8) {
        return false;
    }
    uint32_t magic = 0;
    read_u32(data, len, 0, true, magic);
    const bool thin = magic == 0xFEEDFACE || magic == 0xFEEDFACF;
    const bool fat = magic == 0xBEBAFECA || magic == 0xCAFEBABE;
    if (!thin && !fat) {
        return false;
    }
    info.kind = fat ? "macho-fat" : (magic == 0xFEEDFACF ? "macho64" : "macho32");
    info.bits = magic == 0xFEEDFACF ? 64 : 32;
    info.arch = "arm64/x86_64";
    add_structural(out, "TVX-STRUCT-MACHO-UNSUPPORTED",
                   "Mach-O image: header recognised, deep checks are not implemented");
    return true;
}

/* ------------------------------------------------------------------- IOCs */

struct Ioc {
    std::string type;
    std::string value;
    size_t offset = 0;
};

bool ioc_usable(const std::vector<Ioc> &iocs, const std::string &value) {
    for (const auto &ioc : iocs) {
        if (ioc.value == value) {
            return false;
        }
    }
    return !value.empty();
}

void push_ioc(std::vector<Ioc> &iocs, const char *type, const std::string &value, size_t offset) {
    if (iocs.size() >= kMaxIocs || value.size() < 4 || value.size() > 512) {
        return;
    }
    if (ioc_usable(iocs, value)) {
        iocs.push_back(Ioc{type, value, offset});
    }
}

bool is_url_char(unsigned char c) {
    if (c <= 0x20 || c >= 0x7F) {
        return false;
    }
    switch (c) {
        case '"':
        case '\'':
        case '<':
        case '>':
        case '`':
        case '{':
        case '}':
        case '|':
        case '\\':
        case '^':
            return false;
        default:
            return true;
    }
}

void extract_urls(const uint8_t *data, size_t len, std::vector<Ioc> &iocs) {
    for (size_t index = 0; index + 4 < len; ++index) {
        const bool http = (data[index] == 'h' || data[index] == 'H') &&
                          std::memcmp(data + index, "http", 4) == 0;
        const bool ftp = (data[index] == 'f' || data[index] == 'F') &&
                         std::memcmp(data + index, "ftp:", 4) == 0;
        if (!http && !ftp) {
            continue;
        }
        size_t end = index;
        while (end < len && is_url_char(data[end]) && end - index < 512) {
            end++;
        }
        std::string value(reinterpret_cast<const char *>(data + index), end - index);
        while (!value.empty() && (value.back() == '.' || value.back() == ',' || value.back() == ')')) {
            value.pop_back();
        }
        if (value.size() > 10 && (value.find("://") != std::string::npos)) {
            push_ioc(iocs, "url", value, index);
        }
        index = end > index ? end - 1 : index;
    }
}

void extract_emails(const uint8_t *data, size_t len, std::vector<Ioc> &iocs) {
    for (size_t index = 0; index < len; ++index) {
        if (data[index] != '@') {
            continue;
        }
        size_t start = index;
        while (start > 0 && index - start < 64) {
            const unsigned char c = data[start - 1];
            const bool allowed = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                                 (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-' ||
                                 c == '+';
            if (!allowed) {
                break;
            }
            start--;
        }
        size_t end = index + 1;
        while (end < len && end - index < 128) {
            const unsigned char c = data[end];
            const bool allowed = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                                 (c >= '0' && c <= '9') || c == '.' || c == '-';
            if (!allowed) {
                break;
            }
            end++;
        }
        if (end > index + 1 && start < index) {
            std::string domain(reinterpret_cast<const char *>(data + index + 1), end - index - 1);
            if (domain.find('.') != std::string::npos && domain.find("..") == std::string::npos &&
                domain.size() > 3) {
                std::string value(reinterpret_cast<const char *>(data + start), end - start);
                push_ioc(iocs, "email", value, start);
            }
        }
    }
}

void extract_ipv4(const uint8_t *data, size_t len, std::vector<Ioc> &iocs) {
    size_t index = 0;
    while (index < len) {
        if (!(data[index] >= '0' && data[index] <= '9')) {
            index++;
            continue;
        }
        if (index > 0 && ((data[index - 1] >= '0' && data[index - 1] <= '9') ||
                          data[index - 1] == '.')) {
            index++;
            continue;
        }
        const size_t start = index;
        int octets = 0;
        bool valid = true;
        while (octets < 4) {
            int value = 0;
            int digits = 0;
            while (index < len && data[index] >= '0' && data[index] <= '9' && digits < 3) {
                value = value * 10 + (data[index] - '0');
                index++;
                digits++;
            }
            if (digits == 0 || value > 255) {
                valid = false;
                break;
            }
            octets++;
            if (octets < 4) {
                if (index >= len || data[index] != '.') {
                    valid = false;
                    break;
                }
                index++;
            }
        }
        if (valid && octets == 4) {
            std::string value(reinterpret_cast<const char *>(data + start), index - start);
            push_ioc(iocs, "ipv4", value, start);
        } else {
            index = start + 1;
        }
    }
}

/* --------------------------------------------------------------- output */

std::string run_scan(const Matcher *matcher, const uint8_t *data, size_t len) {
    std::vector<size_t> hits(matcher->needles.size(), 0);
    std::vector<size_t> first_offset(matcher->needles.size(), 0);
    std::vector<bool> seen(matcher->needles.size(), false);
    std::vector<size_t> rule_hits(matcher->rules.size(), 0);
    std::vector<size_t> rule_first(matcher->rules.size(), 0);
    std::vector<bool> rule_first_set(matcher->rules.size(), false);
    std::vector<std::vector<bool>> rule_needle_seen(matcher->rules.size());

    for (size_t rule = 0; rule < matcher->rules.size(); ++rule) {
        rule_needle_seen[rule].assign(matcher->rules[rule].needles.size(), false);
    }

    std::vector<size_t> needle_rule(matcher->needles.size(), 0);
    std::vector<size_t> needle_slot(matcher->needles.size(), 0);
    for (size_t rule = 0; rule < matcher->rules.size(); ++rule) {
        const Rule &entry = matcher->rules[rule];
        for (size_t slot = 0; slot < entry.needles.size(); ++slot) {
            const int needle = entry.needles[slot];
            if (needle >= 0 && static_cast<size_t>(needle) < needle_rule.size()) {
                needle_rule[needle] = rule;
                needle_slot[needle] = slot;
            }
        }
    }

    auto sink = [&](int needle, size_t end_offset) {
        if (needle < 0 || static_cast<size_t>(needle) >= hits.size()) {
            return;
        }
        if (rule_hits[needle_rule[needle]] >= kMaxHitsPerRule) {
            return;
        }
        hits[needle]++;
        if (!seen[needle]) {
            seen[needle] = true;
            first_offset[needle] = end_offset;
        }
        const size_t rule = needle_rule[needle];
        rule_hits[rule]++;
        rule_needle_seen[rule][needle_slot[needle]] = true;
        if (!rule_first_set[rule]) {
            rule_first_set[rule] = true;
            rule_first[rule] = end_offset;
        }
    };

    matcher->sensitive.scan(data, len, sink);
    matcher->insensitive.scan(data, len, sink);

    ImageInfo info;
    std::vector<Structural> structural;
    const bool elfish = analyze_elf(data, len, info, structural);
    const bool peish = !elfish && analyze_pe(data, len, info, structural);
    const bool macho = !elfish && !peish && analyze_macho(data, len, info, structural);
    (void)macho;

    if (!elfish && !peish && len >= 2 && data[0] == '#' && data[1] == '!') {
        info.kind = "script";
        size_t end = 2;
        while (end < len && data[end] != '\n' && end < 128) {
            end++;
        }
        std::string interpreter(reinterpret_cast<const char *>(data + 2), end - 2);
        add_structural(structural, "TVX-STRUCT-SCRIPT",
                       "script interpreter: " + interpreter);
    }

    std::vector<Ioc> iocs;
    extract_urls(data, len, iocs);
    extract_emails(data, len, iocs);
    extract_ipv4(data, len, iocs);

    std::string out;
    out.reserve(2048);
    char number[64];

    out += "{\"version\":1,\"size\":";
    std::snprintf(number, sizeof(number), "%zu", len);
    out += number;
    out += ",\"kind\":\"";
    out += json_escape(info.kind);
    out += "\",\"arch\":\"";
    out += json_escape(info.arch);
    out += "\",\"bits\":";
    std::snprintf(number, sizeof(number), "%d", info.bits);
    out += number;

    std::snprintf(number, sizeof(number), ",\"entropy\":%.4f", shannon_entropy(data, len));
    out += number;
    std::snprintf(number, sizeof(number), ",\"max_window_entropy\":%.4f",
                  max_window_entropy(data, len));
    out += number;
    std::snprintf(number, sizeof(number), ",\"longest_base64_run\":%zu",
                  longest_base64_run(data, len));
    out += number;

    out += ",\"rules\":[";
    bool first_rule = true;
    for (size_t rule = 0; rule < matcher->rules.size(); ++rule) {
        const Rule &entry = matcher->rules[rule];
        bool fired = false;
        if (entry.require_all) {
            fired = !entry.needles.empty();
            for (bool hit : rule_needle_seen[rule]) {
                if (!hit) {
                    fired = false;
                    break;
                }
            }
        } else {
            fired = rule_hits[rule] > 0;
        }
        if (!fired) {
            continue;
        }
        if (!first_rule) {
            out += ',';
        }
        first_rule = false;
        out += "{\"id\":\"";
        out += json_escape(entry.id);
        out += "\",\"hits\":";
        std::snprintf(number, sizeof(number), "%zu", rule_hits[rule]);
        out += number;
        out += ",\"first_offset\":";
        std::snprintf(number, sizeof(number), "%zu", rule_first[rule]);
        out += number;
        out += "}";
    }

    out += "],\"structural\":[";
    for (size_t index = 0; index < structural.size(); ++index) {
        if (index > 0) {
            out += ',';
        }
        out += "{\"id\":\"";
        out += json_escape(structural[index].id);
        out += "\",\"detail\":\"";
        out += json_escape(structural[index].detail);
        out += "\"}";
    }

    out += "],\"iocs\":[";
    for (size_t index = 0; index < iocs.size(); ++index) {
        if (index > 0) {
            out += ',';
        }
        out += "{\"type\":\"";
        out += json_escape(iocs[index].type);
        out += "\",\"value\":\"";
        out += json_escape(iocs[index].value);
        out += "\",\"offset\":";
        std::snprintf(number, sizeof(number), "%zu", iocs[index].offset);
        out += number;
        out += "}";
    }
    out += "]}";

    return out;
}

bool valid_needle(const char *needle, size_t length) {
    if (needle == nullptr || length == 0 || length > kMaxNeedleLen) {
        return false;
    }
    return std::memchr(needle, 0, length) == nullptr;
}

/* Lowercase copy used for the case-insensitive automaton. */
std::vector<unsigned char> lowercased(const char *needle, size_t length) {
    std::vector<unsigned char> out(length);
    for (size_t index = 0; index < length; ++index) {
        unsigned char c = static_cast<unsigned char>(needle[index]);
        out[index] = (c >= 'A' && c <= 'Z') ? static_cast<unsigned char>(c + 32) : c;
    }
    return out;
}

} /* namespace */

extern "C" {

const char *tv_core_version(void) { return "torvex-native/1.0.0"; }

tv_matcher *tv_matcher_create(void) {
    try {
        return reinterpret_cast<tv_matcher *>(new (std::nothrow) Matcher());
    } catch (...) {
        return nullptr;
    }
}

int tv_matcher_add_rule(tv_matcher *matcher, const char *rule_id, int require_all,
                        const char *const *needles, const size_t *lengths, const int *nocase,
                        size_t needle_count) {
    if (matcher == nullptr || rule_id == nullptr || needles == nullptr || lengths == nullptr) {
        return 1;
    }
    Matcher *self = reinterpret_cast<Matcher *>(matcher);
    if (self->built) {
        return 2;
    }
    if (self->rules.size() >= kMaxRules || needle_count == 0 ||
        needle_count > kMaxNeedlesPerRule) {
        return 3;
    }
    for (size_t index = 0; index < needle_count; ++index) {
        if (!valid_needle(needles[index], lengths[index])) {
            return 4;
        }
    }

    try {
        Rule rule;
        rule.id = rule_id;
        rule.require_all = require_all != 0;
        for (size_t index = 0; index < needle_count; ++index) {
            const int needle_index = static_cast<int>(self->needles.size());
            Needle needle;
            needle.rule = static_cast<int>(self->rules.size());
            needle.nocase = nocase != nullptr && nocase[index] != 0;
            needle.bytes.assign(reinterpret_cast<const unsigned char *>(needles[index]),
                                reinterpret_cast<const unsigned char *>(needles[index]) +
                                    lengths[index]);
            self->needles.push_back(std::move(needle));
            rule.needles.push_back(needle_index);
        }
        self->rules.push_back(std::move(rule));
    } catch (...) {
        return 5;
    }
    return 0;
}

int tv_matcher_build(tv_matcher *matcher) {
    if (matcher == nullptr) {
        return 1;
    }
    Matcher *self = reinterpret_cast<Matcher *>(matcher);
    try {
        size_t sensitive_count = 0;
        size_t insensitive_count = 0;
        for (const auto &needle : self->needles) {
            if (needle.nocase) {
                insensitive_count += needle.bytes.size();
            } else {
                sensitive_count += needle.bytes.size();
            }
        }
        self->sensitive.reserve(sensitive_count + 8);
        self->insensitive.reserve(insensitive_count + 8);

        for (size_t index = 0; index < self->needles.size(); ++index) {
            const auto &needle = self->needles[index];
            if (needle.nocase) {
                self->insensitive.add(
                    lowercased(reinterpret_cast<const char *>(needle.bytes.data()),
                               needle.bytes.size()),
                    static_cast<int>(index));
            } else {
                self->sensitive.add(needle.bytes, static_cast<int>(index));
            }
        }
        if (!self->needles.empty()) {
            self->sensitive.mark_outputs();
            self->insensitive.mark_outputs();
        }
        self->insensitive.set_fold(true);
        self->sensitive.build();
        self->insensitive.build();
        self->built = true;
    } catch (...) {
        return 2;
    }
    return 0;
}

size_t tv_matcher_rule_count(const tv_matcher *matcher) {
    return matcher == nullptr ? 0 : reinterpret_cast<const Matcher *>(matcher)->rules.size();
}

char *tv_scan(const tv_matcher *matcher, const uint8_t *data, size_t len) {
    if (matcher == nullptr || data == nullptr) {
        return nullptr;
    }
    const Matcher *self = reinterpret_cast<const Matcher *>(matcher);
    if (!self->built) {
        return nullptr;
    }
    if (len > kMaxScanBytes) {
        len = kMaxScanBytes;
    }
    try {
        const std::string json = run_scan(self, data, len);
        char *out = static_cast<char *>(std::malloc(json.size() + 1));
        if (out == nullptr) {
            return nullptr;
        }
        std::memcpy(out, json.data(), json.size());
        out[json.size()] = '\0';
        return out;
    } catch (...) {
        return nullptr;
    }
}

void tv_free(char *value) { std::free(value); }

void tv_matcher_destroy(tv_matcher *matcher) {
    delete reinterpret_cast<Matcher *>(matcher);
}

} /* extern "C" */
