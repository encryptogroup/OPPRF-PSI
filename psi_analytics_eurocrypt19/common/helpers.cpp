//
// \author Oleksandr Tkachenko
// \email tkachenko@encrypto.cs.tu-darmstadt.de
// \organization Cryptography and Privacy Engineering Group (ENCRYPTO)
// \TU Darmstadt, Computer Science department
//
// \copyright The MIT License. Copyright Oleksandr Tkachenko
//
// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the Software
// is furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
// INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR
// A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
// HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE
// OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

#include "helpers.h"

#include <algorithm>
#include <cassert>
#include <random>
#include <unordered_set>

#include "HashingTables/common/hashing.h"
#include "constants.h"

namespace ENCRYPTO {

std::vector<uint64_t> GeneratePseudoRandomElements(const std::size_t n, const std::size_t bitlen,
                                                   const std::size_t seed) {
  std::vector<uint64_t> elements;
  elements.reserve(n);

  std::mt19937 engine(seed);

  bool not_finished = true;
  while (not_finished) {
    std::uniform_int_distribution<std::uint64_t> dist(0, (1ull << bitlen) - 1);

    const auto my_rand = [&engine, &dist]() { return dist(engine); };
    while (elements.size() != n) {
      elements.push_back(my_rand());
    }
    // check that the elements are unique
    // if there are duplicated, remove them and add some more random elements, then recheck
    std::unordered_set<uint64_t> s;
    for (auto e : elements) {
      s.insert(e);
    }
    elements.assign(s.begin(), s.end());

    if (elements.size() == n) {
      not_finished = false;
    }
  }

  std::sort(elements.begin(), elements.end());
  for (auto i = 1ull; i < elements.size(); ++i) {
    assert(elements.at(i - 1) != elements.at(i));
  }

  for (auto &e : elements) {
    e = HashingTable::ElementToHash(e) & __61_bit_mask;
  }

  return elements;
}

std::vector<uint64_t> GenerateSequentialElements(const std::size_t n) {
  std::vector<uint64_t> elements(n);
  std::size_t i = 0;
  std::generate(elements.begin(), elements.end(), [&i]() mutable { return i++; });

  for (auto &e : elements) {
    e = HashingTable::ElementToHash(e) & __61_bit_mask;
  }

  return elements;
}

}