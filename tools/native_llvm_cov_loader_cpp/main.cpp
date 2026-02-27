// Copyright 2026 Fuzz Introspector Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <array>
#include <cctype>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <map>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include <rapidjson/document.h>
#include <rapidjson/error/en.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>

namespace {

struct OutputPayload {
  std::map<std::string, std::vector<std::array<long long, 2>>> covmap;
  std::map<std::string, std::vector<long long>> branch_cov_map;
  std::vector<std::string> coverage_files;
};

std::string Trim(std::string value) {
  size_t start = 0;
  while (start < value.size() &&
         std::isspace(static_cast<unsigned char>(value[start])) != 0) {
    ++start;
  }

  size_t end = value.size();
  while (end > start &&
         std::isspace(static_cast<unsigned char>(value[end - 1])) != 0) {
    --end;
  }

  return value.substr(start, end - start);
}

bool EndsWith(const std::string& text, char last) {
  return !text.empty() && text.back() == last;
}

std::vector<std::string> Split(const std::string& text, char separator) {
  std::vector<std::string> out;
  std::string current;
  for (char ch : text) {
    if (ch == separator) {
      out.push_back(current);
      current.clear();
    } else {
      current.push_back(ch);
    }
  }
  out.push_back(current);
  return out;
}

bool IsIdentifierChar(char ch) {
  return std::isalnum(static_cast<unsigned char>(ch)) != 0 || ch == '_';
}

size_t FindStandaloneKeyword(std::string_view text,
                             const std::string& keyword) {
  if (keyword.empty()) {
    return std::string::npos;
  }

  size_t cursor = text.find(keyword);
  while (cursor != std::string::npos) {
    const size_t after = cursor + keyword.size();
    const bool left_ok =
        cursor == 0 || !IsIdentifierChar(text[cursor - 1]);
    const bool right_ok =
        after >= text.size() || !IsIdentifierChar(text[after]);
    if (left_ok && right_ok) {
      return cursor;
    }
    cursor = text.find(keyword, cursor + 1);
  }

  return std::string::npos;
}

bool ParsePipeSeparatedCoverageFields(const std::string& line,
                                      std::string_view* line_number_raw,
                                      std::string_view* hit_count_raw,
                                      std::string_view* source_fragment_raw) {
  const std::string_view line_view(line);

  const size_t first_pipe = line_view.find('|');
  if (first_pipe == std::string::npos) {
    return false;
  }

  *line_number_raw = line_view.substr(0, first_pipe);

  const size_t second_pipe = line_view.find('|', first_pipe + 1);
  if (second_pipe == std::string::npos) {
    *hit_count_raw = line_view.substr(first_pipe + 1);
    *source_fragment_raw = std::string_view();
    return true;
  }

  *hit_count_raw = line_view.substr(first_pipe + 1,
                                    second_pipe - first_pipe - 1);

  const size_t third_pipe = line_view.find('|', second_pipe + 1);
  if (third_pipe == std::string::npos) {
    *source_fragment_raw = line_view.substr(second_pipe + 1);
  } else {
    *source_fragment_raw =
        line_view.substr(second_pipe + 1, third_pipe - second_pipe - 1);
  }
  return true;
}

void ReplaceAllInPlace(std::string* value,
                       const std::string& needle,
                       const std::string& replacement) {
  if (needle.empty()) {
    return;
  }
  size_t cursor = 0;
  while ((cursor = value->find(needle, cursor)) != std::string::npos) {
    value->replace(cursor, needle.size(), replacement);
    cursor += replacement.size();
  }
}

bool ParseIntegerStrict(const std::string& raw, long long* parsed) {
  try {
    size_t idx = 0;
    const long long value = std::stoll(raw, &idx, 10);
    if (idx != raw.size()) {
      return false;
    }
    *parsed = value;
    return true;
  } catch (const std::exception&) {
    return false;
  }
}

bool ParseDoubleStrict(const std::string& raw, double* parsed) {
  try {
    size_t idx = 0;
    const double value = std::stod(raw, &idx);
    if (idx != raw.size()) {
      return false;
    }
    *parsed = value;
    return true;
  } catch (const std::exception&) {
    return false;
  }
}

bool ExtractHitCount(const std::string& raw, long long* count) {
  const std::string trimmed = Trim(raw);
  if (trimmed.empty()) {
    return false;
  }

  if (trimmed.find('e') != std::string::npos ||
      trimmed.find('E') != std::string::npos) {
    double parsed = 0.0;
    if (!ParseDoubleStrict(trimmed, &parsed)) {
      return false;
    }
    *count = static_cast<long long>(parsed);
    return true;
  }

  const char last = trimmed.back();
  if (std::isdigit(static_cast<unsigned char>(last)) != 0) {
    return ParseIntegerStrict(trimmed, count);
  }

  double multiplier = 0.0;
  switch (last) {
    case 'k':
      multiplier = 1000.0;
      break;
    case 'M':
      multiplier = 1000000.0;
      break;
    case 'G':
      multiplier = 1000000000.0;
      break;
    default:
      return false;
  }

  if (trimmed.size() < 2) {
    return false;
  }
  const std::string number_part = trimmed.substr(0, trimmed.size() - 1);
  double parsed = 0.0;
  if (!ParseDoubleStrict(number_part, &parsed)) {
    return false;
  }

  *count = static_cast<long long>(parsed * multiplier);
  return true;
}

bool ParseBranchLine(const std::string& line,
                     long long* line_number,
                     long long* column_number,
                     long long* true_hit,
                     long long* false_hit) {
  const size_t branch_start_raw = line.find("Branch (");
  if (branch_start_raw == std::string::npos) {
    return false;
  }
  const size_t branch_start = branch_start_raw + std::string("Branch (").size();

  const size_t branch_end = line.find(')', branch_start);
  if (branch_end == std::string::npos) {
    return false;
  }

  const std::string location = line.substr(branch_start, branch_end - branch_start);
  const std::vector<std::string> location_parts = Split(location, ':');
  if (location_parts.size() != 2) {
    return false;
  }

  const std::string line_raw = Trim(location_parts[0]);
  const std::string column_raw = Trim(location_parts[1]);
  if (!ParseIntegerStrict(line_raw, line_number) ||
      !ParseIntegerStrict(column_raw, column_number)) {
    return false;
  }

  const size_t true_start_raw = line.find("True:");
  const size_t false_start_raw = line.find("False:");
  if (true_start_raw == std::string::npos || false_start_raw == std::string::npos) {
    return false;
  }

  const size_t true_start = true_start_raw + std::string("True:").size();
  const size_t comma_pos = line.find(',', true_start);
  if (comma_pos == std::string::npos) {
    return false;
  }

  const std::string true_raw = Trim(line.substr(true_start, comma_pos - true_start));

  const size_t false_start = false_start_raw + std::string("False:").size();
  std::string false_raw = Trim(line.substr(false_start));
  while (!false_raw.empty() && false_raw.back() == ']') {
    false_raw.pop_back();
  }
  false_raw = Trim(false_raw);

  return ExtractHitCount(true_raw, true_hit) && ExtractHitCount(false_raw, false_hit);
}

std::string ExtractFunctionName(const std::string& line) {
  const std::vector<std::string> parts = Split(line, ':');
  if (parts.size() == 3) {
    std::string function_name = parts[1];
    ReplaceAllInPlace(&function_name, " ", "");
    ReplaceAllInPlace(&function_name, ":", "");
    return function_name;
  }
  std::string normalized = line;
  ReplaceAllInPlace(&normalized, " ", "");
  ReplaceAllInPlace(&normalized, ":", "");
  return normalized;
}

std::vector<std::string> ParseCoverageReportsJson(const std::string& raw_input) {
  rapidjson::Document input;
  input.Parse(raw_input.c_str());
  if (input.HasParseError()) {
    throw std::runtime_error("invalid JSON input: " +
                             std::string(rapidjson::GetParseError_En(
                                 input.GetParseError())) +
                             " at offset " + std::to_string(input.GetErrorOffset()));
  }
  if (!input.IsObject()) {
    throw std::runtime_error("expected top-level JSON object");
  }

  const auto reports_it = input.FindMember("coverage_reports");
  if (reports_it == input.MemberEnd()) {
    throw std::runtime_error("missing required key: coverage_reports");
  }
  if (!reports_it->value.IsArray()) {
    throw std::runtime_error("coverage_reports must be an array");
  }

  std::vector<std::string> coverage_reports;
  coverage_reports.reserve(reports_it->value.Size());
  for (const auto& report_value : reports_it->value.GetArray()) {
    if (!report_value.IsString()) {
      throw std::runtime_error("coverage_reports entries must be strings");
    }
    coverage_reports.emplace_back(report_value.GetString(),
                                  report_value.GetStringLength());
  }
  return coverage_reports;
}

std::string RenderOutputJson(const OutputPayload& payload) {
  rapidjson::Document output(rapidjson::kObjectType);
  rapidjson::Document::AllocatorType& allocator = output.GetAllocator();

  rapidjson::Value covmap(rapidjson::kObjectType);
  for (const auto& item : payload.covmap) {
    rapidjson::Value function_name;
    function_name.SetString(item.first.data(),
                            static_cast<rapidjson::SizeType>(item.first.size()),
                            allocator);

    rapidjson::Value coverage_points(rapidjson::kArrayType);
    coverage_points.Reserve(static_cast<rapidjson::SizeType>(item.second.size()),
                            allocator);
    for (const auto& entry : item.second) {
      rapidjson::Value point(rapidjson::kArrayType);
      point.PushBack(static_cast<int64_t>(entry[0]), allocator);
      point.PushBack(static_cast<int64_t>(entry[1]), allocator);
      coverage_points.PushBack(point, allocator);
    }
    covmap.AddMember(function_name, coverage_points, allocator);
  }
  output.AddMember("covmap", covmap, allocator);

  rapidjson::Value branch_cov_map(rapidjson::kObjectType);
  for (const auto& item : payload.branch_cov_map) {
    rapidjson::Value branch_name;
    branch_name.SetString(item.first.data(),
                          static_cast<rapidjson::SizeType>(item.first.size()),
                          allocator);

    rapidjson::Value branch_values(rapidjson::kArrayType);
    branch_values.Reserve(static_cast<rapidjson::SizeType>(item.second.size()),
                          allocator);
    for (long long value : item.second) {
      branch_values.PushBack(static_cast<int64_t>(value), allocator);
    }
    branch_cov_map.AddMember(branch_name, branch_values, allocator);
  }
  output.AddMember("branch_cov_map", branch_cov_map, allocator);

  rapidjson::Value coverage_files(rapidjson::kArrayType);
  coverage_files.Reserve(
      static_cast<rapidjson::SizeType>(payload.coverage_files.size()), allocator);
  for (const std::string& path : payload.coverage_files) {
    rapidjson::Value value;
    value.SetString(path.data(), static_cast<rapidjson::SizeType>(path.size()),
                    allocator);
    coverage_files.PushBack(value, allocator);
  }
  output.AddMember("coverage_files", coverage_files, allocator);

  rapidjson::StringBuffer buffer;
  rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
  output.Accept(writer);
  return buffer.GetString();
}

void ParseCoverageReport(const std::string& path, OutputPayload* out) {
  std::ifstream file(path);
  if (!file.is_open()) {
    throw std::runtime_error("failed to open coverage report: " + path);
  }

  std::string current_func;
  std::string switch_string;
  long long switch_line_number = -1;
  std::set<long long> case_line_numbers;

  std::string line;
  while (std::getline(file, line)) {
    const std::string trimmed = Trim(line);
    if (trimmed.empty()) {
      continue;
    }

    if (EndsWith(trimmed, ':') && trimmed.find('|') == std::string::npos) {
      current_func = ExtractFunctionName(line);
      switch_string.clear();
      switch_line_number = -1;
      case_line_numbers.clear();
      // Keep parity with Python loader behavior: latest section wins.
      out->covmap[current_func].clear();
      continue;
    }

    if (current_func.empty()) {
      continue;
    }

    if (line.find("Branch (") != std::string::npos &&
        line.find("True:") != std::string::npos &&
        line.find("False:") != std::string::npos) {
      long long branch_line = 0;
      long long branch_col = 0;
      long long true_hit = 0;
      long long false_hit = 0;
      if (ParseBranchLine(line, &branch_line, &branch_col, &true_hit, &false_hit)) {
        if (switch_line_number > 0 && branch_line == switch_line_number &&
            !switch_string.empty()) {
          out->branch_cov_map[switch_string] = {true_hit, false_hit};
        } else if (case_line_numbers.find(branch_line) != case_line_numbers.end() &&
                   !switch_string.empty()) {
          auto existing = out->branch_cov_map.find(switch_string);
          if (existing == out->branch_cov_map.end()) {
            out->branch_cov_map[switch_string] = {true_hit, false_hit, true_hit};
          } else {
            existing->second.push_back(true_hit);
          }
        } else {
          const std::string branch_key =
              current_func + ":" + std::to_string(branch_line) + "," +
              std::to_string(branch_col);
          out->branch_cov_map[branch_key] = {true_hit, false_hit};
        }
      }
    }

    std::string_view line_number_raw;
    std::string_view hit_count_raw;
    std::string_view source_fragment_view;
    if (!ParsePipeSeparatedCoverageFields(line, &line_number_raw, &hit_count_raw,
                                          &source_fragment_view)) {
      continue;
    }

    long long line_no = 0;
    if (!ParseIntegerStrict(Trim(std::string(line_number_raw)), &line_no)) {
      continue;
    }

    const std::string_view source_fragment(source_fragment_view);

    const size_t switch_idx = FindStandaloneKeyword(source_fragment, "switch");
    const size_t switch_open_paren = switch_idx == std::string::npos
                                         ? std::string::npos
                                         : source_fragment.find(
                                               '(', switch_idx +
                                                        std::string("switch").size());
    const bool is_switch_statement =
        switch_idx != std::string::npos &&
        switch_open_paren != std::string::npos &&
        source_fragment.find(')', switch_open_paren + 1) != std::string::npos;
    if (is_switch_statement) {
      switch_line_number = line_no;
      case_line_numbers.clear();
      const long long column_number = static_cast<long long>(switch_idx) + 1;
      switch_string = current_func + ":" + std::to_string(line_no) + "," +
                      std::to_string(column_number);
    }
    const size_t case_idx = FindStandaloneKeyword(source_fragment, "case");
    if (!switch_string.empty() && case_idx != std::string::npos &&
        source_fragment.find(':', case_idx + std::string("case").size()) !=
            std::string::npos) {
      case_line_numbers.insert(line_no);
    }

    long long hit_count = 0;
    if (!ExtractHitCount(std::string(hit_count_raw), &hit_count)) {
      if (line.find(" 0| ") != std::string::npos ||
          line.find("| 0|") != std::string::npos) {
        hit_count = 0;
      } else {
        continue;
      }
    }

    out->covmap[current_func].push_back({line_no, hit_count});
  }
}

int Run() {
  std::ostringstream raw_input_stream;
  raw_input_stream << std::cin.rdbuf();
  const std::vector<std::string> coverage_reports =
      ParseCoverageReportsJson(raw_input_stream.str());

  OutputPayload output;
  output.coverage_files = coverage_reports;
  for (const auto& report_path : coverage_reports) {
    ParseCoverageReport(report_path, &output);
  }

  std::cout << RenderOutputJson(output) << "\n";
  return 0;
}

}  // namespace

int main() {
  try {
    return Run();
  } catch (const std::exception& err) {
    std::cerr << err.what() << "\n";
    return 1;
  }
}
