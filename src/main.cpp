#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace {

bool digit(char c) { return c >= '0' && c <= '9'; }
bool letter(char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}
bool alnum(char c) { return letter(c) || digit(c); }
bool candidate_char(char c) {
    return alnum(c) || c == '.' || c == '_' || c == '-' || c == '@';
}

bool email(std::string_view text) {
    enum class State { local_start, local_end, local_inner,
                       domain_start, domain_end, domain_inner };
    State state = State::local_start;
    bool domain_dot = false;
    bool label_letters = true;
    // Only the distinction 0 / 1 / at least 2 matters for the TLD.
    unsigned label_length = 0;
    for (char c : text) {
        switch (state) {
        case State::local_start:
            if (!alnum(c)) return false;
            state = State::local_end;
            break;
        case State::local_end:
            if (alnum(c)) break;
            if (c == '_' || c == '-') state = State::local_inner;
            else if (c == '.') state = State::local_start;
            else if (c == '@') state = State::domain_start;
            else return false;
            break;
        case State::local_inner:
            if (alnum(c)) state = State::local_end;
            else if (c != '_' && c != '-') return false;
            break;
        case State::domain_start:
            if (!alnum(c)) return false;
            label_letters = letter(c);
            label_length = 1;
            state = State::domain_end;
            break;
        case State::domain_end:
        case State::domain_inner:
            if (alnum(c) || c == '-') {
                label_letters = label_letters && letter(c);
                if (label_length < 2) ++label_length;
                state = c == '-' ? State::domain_inner : State::domain_end;
            } else if (c == '.' && state == State::domain_end) {
                domain_dot = true;
                state = State::domain_start;
            } else return false;
            break;
        }
    }
    return state == State::domain_end && domain_dot &&
           label_letters && label_length == 2;
}

bool phone(std::string_view text) {
    unsigned state = 0;
    for (char c : text) {
        if (!digit(c) || state == 11) return false;
        if ((state == 0 && c != '0') || (state == 1 && c != '9')) return false;
        ++state;
    }
    return state == 11;
}

bool ipv4(std::string_view text) {
    unsigned part = 0, digits = 0, value = 0;
    for (char c : text) {
        if (digit(c)) {
            if (digits == 3 || (digits != 0 && value == 0)) return false;
            value = value * 10 + static_cast<unsigned>(c - '0');
            if (value > 255) return false;
            ++digits;
        } else if (c == '.' && digits != 0 && part < 3) {
            ++part;
            digits = value = 0;
        } else return false;
    }
    return part == 3 && digits != 0;
}

// Validate one Unicode scalar and return its byte width. Reject overlong
// encodings, surrogate code points, and values beyond U+10FFFF.
std::size_t utf8_width(const std::string& text, std::size_t pos) {
    const auto first = static_cast<unsigned char>(text[pos]);
    if (first < 0x80) return 1;
    unsigned width, value, minimum;
    if (first >= 0xc2 && first <= 0xdf) {
        width = 2; value = first & 0x1f; minimum = 0x80;
    } else if (first >= 0xe0 && first <= 0xef) {
        width = 3; value = first & 0x0f; minimum = 0x800;
    } else if (first >= 0xf0 && first <= 0xf4) {
        width = 4; value = first & 0x07; minimum = 0x10000;
    } else throw std::runtime_error("invalid UTF-8 at byte " + std::to_string(pos + 1));
    if (text.size() - pos < width)
        throw std::runtime_error("truncated UTF-8 at byte " + std::to_string(pos + 1));
    for (unsigned i = 1; i < width; ++i) {
        const auto next = static_cast<unsigned char>(text[pos + i]);
        if ((next & 0xc0) != 0x80)
            throw std::runtime_error("invalid UTF-8 at byte " + std::to_string(pos + 1));
        value = (value << 6) | (next & 0x3f);
    }
    if (value < minimum || value > 0x10ffff || (value >= 0xd800 && value <= 0xdfff))
        throw std::runtime_error("invalid UTF-8 at byte " + std::to_string(pos + 1));
    return width;
}

struct Finding {
    const char* type;
    std::size_t line, column, length;
};

struct Result {
    std::string sanitized;
    std::vector<Finding> findings;
};

Result scan(const std::string& input) {
    Result result;
    std::size_t pos = 0, line = 1, column = 1;
    while (pos < input.size()) {
        if (candidate_char(input[pos])) {
            const std::size_t start = pos;
            while (pos < input.size() && candidate_char(input[pos])) ++pos;
            std::size_t end = pos;
            while (end > start && input[end - 1] == '.') --end;
            const std::string_view candidate(input.data() + start, end - start);
            const char* type = nullptr;
            if (email(candidate)) type = "EMAIL";
            else if (phone(candidate)) type = "PHONE";
            else if (ipv4(candidate)) type = "IP";
            if (type) {
                result.findings.push_back({type, line, column, end - start});
                result.sanitized += '[';
                result.sanitized += type;
                result.sanitized += ']';
                result.sanitized.append(input, end, pos - end);
            } else result.sanitized.append(input, start, pos - start);
            column += pos - start;
        } else {
            const std::size_t width = utf8_width(input, pos);
            if (input[pos] == '\r' && pos + 1 < input.size() && input[pos + 1] == '\n') {
                result.sanitized.append(input, pos, 2);
                pos += 2;
                ++line;
                column = 1;
            } else {
                result.sanitized.append(input, pos, width);
                if (input[pos] == '\n') { ++line; column = 1; }
                else ++column;
                pos += width;
            }
        }
    }
    return result;
}

std::string report(const std::vector<Finding>& findings) {
    std::string json = "{\n  \"total_detected\": " + std::to_string(findings.size()) +
                       ",\n  \"findings\": [";
    for (std::size_t i = 0; i < findings.size(); ++i) {
        const auto& f = findings[i];
        json += i == 0 ? "\n" : ",\n";
        json += "    {\"type\": \"" + std::string(f.type) + "\", \"line\": " +
                std::to_string(f.line) + ", \"column\": " + std::to_string(f.column) +
                ", \"length\": " + std::to_string(f.length) + "}";
    }
    if (!findings.empty()) json += '\n';
    json += "  ]\n}\n";
    return json;
}

void write_file(const char* path, const std::string& content) {
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    if (!output) throw std::runtime_error(std::string("cannot open output: ") + path);
    output.write(content.data(), static_cast<std::streamsize>(content.size()));
    output.close();
    if (!output) throw std::runtime_error(std::string("cannot write output: ") + path);
}

} // namespace

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: privacy-scanner INPUT\n";
        return 1;
    }
    try {
        for (const char* output : {"sanitized.txt", "report.json"}) {
            if (std::filesystem::is_symlink(output))
                throw std::runtime_error("output must not be a symbolic link");
            if (std::filesystem::exists(output) && std::filesystem::equivalent(argv[1], output))
                throw std::runtime_error("input must differ from sanitized.txt and report.json");
        }
        if (std::filesystem::exists("sanitized.txt") && std::filesystem::exists("report.json") &&
            std::filesystem::equivalent("sanitized.txt", "report.json"))
            throw std::runtime_error("outputs must be different files");
        std::ifstream input(argv[1], std::ios::binary);
        if (!input) throw std::runtime_error("cannot open input");
        const std::string text((std::istreambuf_iterator<char>(input)), {});
        if (input.bad()) throw std::runtime_error("cannot read input");
        const auto result = scan(text);
        const auto json = report(result.findings);
        write_file("sanitized.txt", result.sanitized);
        write_file("report.json", json);
    } catch (const std::exception& error) {
        std::cerr << "privacy-scanner: " << error.what() << '\n';
        return 1;
    }
}
