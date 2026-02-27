#include <algorithm>
#include <charconv>
#include <cctype>
#include <cmath>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <limits>
#include <optional>
#include <string>
#include <system_error>
#include <vector>

#include <llvm/ADT/SmallString.h>
#include <llvm/Support/Casting.h>
#include <llvm/Support/SourceMgr.h>
#include <llvm/Support/YAMLParser.h>

#include <rapidjson/document.h>
#include <rapidjson/error/en.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>

namespace {

std::string ReadAllStdin() {
  std::string input;
  std::string chunk;
  chunk.resize(4096);
  while (std::cin.good()) {
    std::cin.read(chunk.data(), static_cast<std::streamsize>(chunk.size()));
    const auto read_count = std::cin.gcount();
    if (read_count > 0) {
      input.append(chunk.data(), static_cast<size_t>(read_count));
    }
  }
  return input;
}

std::string Trim(std::string value) {
  const auto not_space = [](unsigned char ch) { return std::isspace(ch) == 0; };
  value.erase(value.begin(),
              std::find_if(value.begin(), value.end(), not_space));
  value.erase(std::find_if(value.rbegin(), value.rend(), not_space).base(),
              value.end());
  return value;
}

bool IsQuotedScalarRaw(const std::string& raw) {
  if (raw.empty()) {
    return false;
  }
  const char marker = raw.front();
  return marker == '\'' || marker == '"';
}

template <typename DigitPredicate>
bool ValidateUnderscoreSeparatedDigits(const std::string& value,
                                       DigitPredicate digit_predicate) {
  if (value.empty()) {
    return false;
  }
  bool previous_underscore = true;
  bool seen_digit = false;
  for (char ch : value) {
    if (ch == '_') {
      if (previous_underscore) {
        return false;
      }
      previous_underscore = true;
      continue;
    }
    if (!digit_predicate(ch)) {
      return false;
    }
    previous_underscore = false;
    seen_digit = true;
  }
  return seen_digit && !previous_underscore;
}

bool IsDecimalDigitsWithUnderscores(const std::string& value) {
  return ValidateUnderscoreSeparatedDigits(value, [](char ch) {
    return ch >= '0' && ch <= '9';
  });
}

bool IsOctalDigitsWithUnderscores(const std::string& value) {
  return ValidateUnderscoreSeparatedDigits(value, [](char ch) {
    return ch >= '0' && ch <= '7';
  });
}

std::string RemoveUnderscores(const std::string& value) {
  std::string normalized;
  normalized.reserve(value.size());
  for (char ch : value) {
    if (ch != '_') {
      normalized.push_back(ch);
    }
  }
  return normalized;
}

std::optional<bool> ParsePyYamlBool(const std::string& value) {
  if (value == "yes" || value == "Yes" || value == "YES" || value == "on" ||
      value == "On" || value == "ON" || value == "true" || value == "True" ||
      value == "TRUE") {
    return true;
  }
  if (value == "no" || value == "No" || value == "NO" || value == "off" ||
      value == "Off" || value == "OFF" || value == "false" ||
      value == "False" || value == "FALSE") {
    return false;
  }
  return std::nullopt;
}

struct ParsedInteger {
  bool is_unsigned = false;
  int64_t signed_value = 0;
  uint64_t unsigned_value = 0;
};

std::optional<ParsedInteger> ParsePyYamlInteger(const std::string& value) {
  if (value.empty()) {
    return std::nullopt;
  }

  bool negative = false;
  std::string body = value;
  if (body.front() == '+' || body.front() == '-') {
    negative = body.front() == '-';
    body.erase(body.begin());
  }
  if (body.empty()) {
    return std::nullopt;
  }

  int base = 10;
  std::string digits = body;
  if (body.rfind("0x", 0) == 0 || body.rfind("0X", 0) == 0) {
    base = 16;
    digits = body.substr(2);
  } else if (body.rfind("0b", 0) == 0 || body.rfind("0B", 0) == 0) {
    base = 2;
    digits = body.substr(2);
  } else if (body.size() > 1 && body.front() == '0') {
    // PyYAML safe_load follows YAML 1.1 octal resolution for plain scalars.
    if (!IsOctalDigitsWithUnderscores(body)) {
      return std::nullopt;
    }
    base = 8;
    digits = body;
  } else {
    if (!IsDecimalDigitsWithUnderscores(body)) {
      return std::nullopt;
    }
  }

  if (digits.empty()) {
    return std::nullopt;
  }
  const std::string normalized = RemoveUnderscores(digits);
  if (normalized.empty()) {
    return std::nullopt;
  }

  uint64_t parsed_unsigned = 0;
  const auto parsed = std::from_chars(normalized.data(),
                                      normalized.data() + normalized.size(),
                                      parsed_unsigned, base);
  if (parsed.ec != std::errc() ||
      parsed.ptr != normalized.data() + normalized.size()) {
    return std::nullopt;
  }

  ParsedInteger result;
  if (negative) {
    constexpr uint64_t kI64AbsMin =
        static_cast<uint64_t>(std::numeric_limits<int64_t>::max()) + 1ULL;
    if (parsed_unsigned > kI64AbsMin) {
      return std::nullopt;
    }
    result.is_unsigned = false;
    if (parsed_unsigned == kI64AbsMin) {
      result.signed_value = std::numeric_limits<int64_t>::min();
    } else {
      result.signed_value = -static_cast<int64_t>(parsed_unsigned);
    }
    return result;
  }

  if (parsed_unsigned <= static_cast<uint64_t>(std::numeric_limits<int64_t>::max())) {
    result.is_unsigned = false;
    result.signed_value = static_cast<int64_t>(parsed_unsigned);
  } else {
    result.is_unsigned = true;
    result.unsigned_value = parsed_unsigned;
  }
  return result;
}

rapidjson::Value ParseScalarValue(const std::string& value,
                                  const std::string& raw_value,
                                  rapidjson::Document::AllocatorType& alloc) {
  std::string trimmed = Trim(value);
  if (IsQuotedScalarRaw(raw_value)) {
    rapidjson::Value string_value;
    string_value.SetString(value.c_str(),
                           static_cast<rapidjson::SizeType>(value.size()),
                           alloc);
    return string_value;
  }

  if (trimmed == "~" || trimmed == "null" || trimmed == "Null" ||
      trimmed == "NULL") {
    rapidjson::Value value;
    value.SetNull();
    return value;
  }

  if (auto parsed_bool = ParsePyYamlBool(trimmed)) {
    return rapidjson::Value(*parsed_bool);
  }

  if (auto parsed_int = ParsePyYamlInteger(trimmed)) {
    if (parsed_int->is_unsigned) {
      return rapidjson::Value(parsed_int->unsigned_value);
    }
    return rapidjson::Value(parsed_int->signed_value);
  }

  try {
    size_t consumed = 0;
    const double parsed_double = std::stod(trimmed, &consumed);
    if (consumed == trimmed.size() && std::isfinite(parsed_double)) {
      return rapidjson::Value(parsed_double);
    }
  } catch (...) {
  }

  rapidjson::Value string_value;
  string_value.SetString(value.c_str(),
                         static_cast<rapidjson::SizeType>(value.size()), alloc);
  return string_value;
}

std::string NodeToString(llvm::yaml::Node* node) {
  if (!node) {
    return "";
  }

  if (const auto* scalar = llvm::dyn_cast<llvm::yaml::ScalarNode>(node)) {
    llvm::SmallString<128> storage;
    return scalar->getValue(storage).str();
  }
  if (const auto* block_scalar =
          llvm::dyn_cast<llvm::yaml::BlockScalarNode>(node)) {
    return block_scalar->getValue().str();
  }
  if (const auto* alias = llvm::dyn_cast<llvm::yaml::AliasNode>(node)) {
    return alias->getName().str();
  }
  return "";
}

rapidjson::Value ConvertYamlNode(llvm::yaml::Node* node,
                                 rapidjson::Document::AllocatorType& alloc) {
  if (!node) {
    rapidjson::Value value;
    value.SetNull();
    return value;
  }

  if (llvm::isa<llvm::yaml::NullNode>(node)) {
    rapidjson::Value value;
    value.SetNull();
    return value;
  }

  if (const auto* scalar = llvm::dyn_cast<llvm::yaml::ScalarNode>(node)) {
    llvm::SmallString<128> storage;
    const std::string parsed_value = scalar->getValue(storage).str();
    const std::string raw_value = scalar->getRawValue().str();
    return ParseScalarValue(parsed_value, raw_value, alloc);
  }

  if (const auto* block_scalar =
          llvm::dyn_cast<llvm::yaml::BlockScalarNode>(node)) {
    rapidjson::Value value;
    const std::string as_string = block_scalar->getValue().str();
    value.SetString(as_string.c_str(),
                    static_cast<rapidjson::SizeType>(as_string.size()), alloc);
    return value;
  }

  if (auto* sequence = llvm::dyn_cast<llvm::yaml::SequenceNode>(node)) {
    rapidjson::Value out(rapidjson::kArrayType);
    for (auto& entry : *sequence) {
      rapidjson::Value entry_value = ConvertYamlNode(&entry, alloc);
      out.PushBack(entry_value, alloc);
    }
    return out;
  }

  if (auto* mapping = llvm::dyn_cast<llvm::yaml::MappingNode>(node)) {
    rapidjson::Value out(rapidjson::kObjectType);
    for (auto& entry : *mapping) {
      llvm::yaml::Node* key_node = entry.getKey();
      llvm::yaml::Node* value_node = entry.getValue();
      const std::string key = NodeToString(key_node);
      rapidjson::Value key_value;
      key_value.SetString(key.c_str(),
                          static_cast<rapidjson::SizeType>(key.size()), alloc);
      rapidjson::Value mapped = ConvertYamlNode(value_node, alloc);
      out.AddMember(key_value, mapped, alloc);
    }
    return out;
  }

  if (const auto* alias = llvm::dyn_cast<llvm::yaml::AliasNode>(node)) {
    rapidjson::Value value;
    const std::string alias_name = alias->getName().str();
    value.SetString(alias_name.c_str(),
                    static_cast<rapidjson::SizeType>(alias_name.size()), alloc);
    return value;
  }

  rapidjson::Value value;
  value.SetNull();
  return value;
}

bool LoadYamlFile(const std::string& path,
                  rapidjson::Value* out,
                  rapidjson::Document::AllocatorType& alloc) {
  std::ifstream file(path, std::ios::binary);
  if (!file.is_open()) {
    return false;
  }
  std::string content((std::istreambuf_iterator<char>(file)),
                      std::istreambuf_iterator<char>());

  llvm::SourceMgr source_mgr;
  std::error_code parse_error;
  llvm::yaml::Stream stream(content, source_mgr, false, &parse_error);
  if (parse_error) {
    return false;
  }

  auto doc_it = stream.begin();
  if (doc_it == stream.end()) {
    rapidjson::Value value;
    value.SetNull();
    *out = std::move(value);
    return true;
  }

  llvm::yaml::Node* root = doc_it->getRoot();
  if (stream.failed()) {
    return false;
  }

  *out = ConvertYamlNode(root, alloc);
  return !stream.failed();
}

bool ExtendPythonStyle(rapidjson::Value* items,
                       rapidjson::Value& parsed,
                       rapidjson::Document::AllocatorType& alloc) {
  if (parsed.IsNull()) {
    return true;
  }

  if (parsed.IsBool()) {
    return !parsed.GetBool();
  }

  if (parsed.IsNumber()) {
    if (parsed.IsInt64()) {
      return parsed.GetInt64() == 0;
    }
    if (parsed.IsUint64()) {
      return parsed.GetUint64() == 0;
    }
    if (parsed.IsDouble()) {
      return parsed.GetDouble() == 0.0;
    }
    return false;
  }

  if (parsed.IsString()) {
    std::string value = parsed.GetString();
    if (value.empty()) {
      return true;
    }
    for (char ch : value) {
      std::string char_string(1, ch);
      rapidjson::Value elem;
      elem.SetString(char_string.c_str(),
                     static_cast<rapidjson::SizeType>(char_string.size()),
                     alloc);
      items->PushBack(elem, alloc);
    }
    return true;
  }

  if (parsed.IsArray()) {
    items->Reserve(items->Size() + parsed.Size(), alloc);
    for (auto& element : parsed.GetArray()) {
      // PushBack(Value&, alloc) moves from the source value, which is safe here
      // because parsed is not used after extension.
      items->PushBack(element, alloc);
    }
    return true;
  }

  if (parsed.IsObject()) {
    if (parsed.ObjectEmpty()) {
      return true;
    }
    std::vector<std::string> keys;
    for (auto member = parsed.MemberBegin(); member != parsed.MemberEnd();
         ++member) {
      keys.emplace_back(member->name.GetString());
    }
    std::sort(keys.begin(), keys.end());
    for (const std::string& key : keys) {
      rapidjson::Value key_value;
      key_value.SetString(key.c_str(),
                          static_cast<rapidjson::SizeType>(key.size()), alloc);
      items->PushBack(key_value, alloc);
    }
    return true;
  }

  return false;
}

void EmitJson(const rapidjson::Value& value) {
  rapidjson::StringBuffer buffer;
  rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
  value.Accept(writer);
  std::cout << buffer.GetString() << "\n";
}

}  // namespace

int main() {
  const std::string raw_input = ReadAllStdin();
  rapidjson::Document payload;
  payload.Parse(raw_input.c_str());
  if (payload.HasParseError() || !payload.IsObject()) {
    std::cerr << "invalid input payload: "
              << rapidjson::GetParseError_En(payload.GetParseError())
              << std::endl;
    return 2;
  }

  rapidjson::Document output_doc;
  output_doc.SetObject();
  auto& alloc = output_doc.GetAllocator();

  if (payload.HasMember("path")) {
    if (!payload["path"].IsString() ||
        std::string(payload["path"].GetString()).empty()) {
      std::cerr << "invalid path payload" << std::endl;
      return 2;
    }
    rapidjson::Value parsed;
    if (!LoadYamlFile(payload["path"].GetString(), &parsed, alloc)) {
      EmitJson(rapidjson::Value().SetNull());
      return 0;
    }
    EmitJson(parsed);
    return 0;
  }

  if (!payload.HasMember("paths") || !payload["paths"].IsArray()) {
    std::cerr << "expected payload with path or paths" << std::endl;
    return 2;
  }

  rapidjson::Value items(rapidjson::kArrayType);
  for (auto& path_value : payload["paths"].GetArray()) {
    if (!path_value.IsString()) {
      std::cerr << "paths must contain only strings" << std::endl;
      return 2;
    }
    rapidjson::Value parsed;
    if (!LoadYamlFile(path_value.GetString(), &parsed, alloc)) {
      std::cerr << "failed to parse " << path_value.GetString() << std::endl;
      continue;
    }
    if (!ExtendPythonStyle(&items, parsed, alloc)) {
      std::cerr << "skipping non-iterable payload in " << path_value.GetString()
                << std::endl;
    }
  }

  rapidjson::Value output(rapidjson::kObjectType);
  rapidjson::Value items_key;
  items_key.SetString("items", 5, alloc);
  output.AddMember(items_key, items, alloc);
  EmitJson(output);
  return 0;
}
