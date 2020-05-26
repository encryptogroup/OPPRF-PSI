//
// \file psi_analytics_eurocrypt19_test.cpp
// \author Oleksandr Tkachenko
// \email tkachenko@encrypto.cs.tu-darmstadt.de
// \organization Cryptography and Privacy Engineering Group (ENCRYPTO)
// \TU Darmstadt, Computer Science department
//
// \copyright The MIT License. Copyright Oleksandr Tkachenko

#include <thread>

#include "gtest/gtest.h"

#include "common/psi_analytics.h"
#include "common/psi_analytics_context.h"

#include "HashingTables/cuckoo_hashing/cuckoo_hashing.h"
#include "HashingTables/simple_hashing/simple_hashing.h"

constexpr std::size_t ITERATIONS = 1;

constexpr std::size_t NELES_2_12 = 1ull << 12, NELES_2_16 = 1ull << 16, NELES_2_20 = 1ull << 20;
constexpr std::size_t POLYNOMIALSIZE_2_12 = 975, POLYNOMIALSIZE_2_16 = 1021,
                      POLYNOMIALSIZE_2_20 = 1024;
constexpr std::size_t NMEGABINS_2_12 = 16, NMEGABINS_2_16 = 248, NMEGABINS_2_20 = 4002;

auto CreateContext(e_role role, uint64_t neles, uint64_t polynomialsize, uint64_t nmegabins) {
  return ENCRYPTO::PsiAnalyticsContext{7777,  // port
                                       role,
                                       61,  // bitlength
                                       neles,
                                       static_cast<uint64_t>(neles * 1.27f),
                                       0,  // # other party's elements, i.e., =neles
                                       1,  // # threads
                                       3,  // # hash functions
                                       1,  // threshold
                                       polynomialsize,
                                       polynomialsize * sizeof(uint64_t),
                                       nmegabins,
                                       1.27f,  // epsilon
                                       "127.0.0.1",
                                       ENCRYPTO::PsiAnalyticsContext::SUM};
}

void PsiAnalyticsThresholdTest(ENCRYPTO::PsiAnalyticsContext client_context,
                               ENCRYPTO::PsiAnalyticsContext server_context) {
  auto client_inputs = ENCRYPTO::GeneratePseudoRandomElements(client_context.neles, 15);
  auto server_inputs = ENCRYPTO::GeneratePseudoRandomElements(server_context.neles, 15);

  auto plain_intersection_size = ENCRYPTO::PlainIntersectionSize(client_inputs, server_inputs);
  assert(plain_intersection_size != 0);
  server_context.threshold = client_context.threshold = plain_intersection_size - 1;

  std::uint64_t psi_client, psi_server;

  // threshold < intersection, should yield 1
  {
    std::thread client_thread(
        [&]() { psi_client = run_psi_analytics(client_inputs, client_context); });
    std::thread server_thread(
        [&]() { psi_server = run_psi_analytics(server_inputs, server_context); });

    client_thread.join();
    server_thread.join();

    ASSERT_EQ(psi_client, 1u);
    ASSERT_EQ(psi_server, 1u);
  }

  server_context.threshold = client_context.threshold = plain_intersection_size + 1;

  // threshold > intersection, should yield 0
  {
    std::thread client_thread(
        [&]() { psi_client = run_psi_analytics(client_inputs, client_context); });
    std::thread server_thread(
        [&]() { psi_server = run_psi_analytics(server_inputs, server_context); });

    client_thread.join();
    server_thread.join();

    ASSERT_EQ(psi_client, 0u);
    ASSERT_EQ(psi_server, 0u);
  }
}

void PsiAnalyticsSumIfGtThresholdTest(ENCRYPTO::PsiAnalyticsContext client_context,
                                      ENCRYPTO::PsiAnalyticsContext server_context) {
  auto client_inputs = ENCRYPTO::GeneratePseudoRandomElements(client_context.neles, 15, 0);
  auto server_inputs = ENCRYPTO::GeneratePseudoRandomElements(client_context.neles, 15, 1);

  auto plain_intersection_size = ENCRYPTO::PlainIntersectionSize(client_inputs, server_inputs);
  assert(plain_intersection_size != 0);
  client_context.threshold = plain_intersection_size - 1;
  server_context.threshold = client_context.threshold;

  std::uint64_t psi_client, psi_server;

  // threshold < intersection, should yield the intersection size
  {
    std::thread client_thread(
        [&]() { psi_client = run_psi_analytics(client_inputs, client_context); });
    std::thread server_thread(
        [&]() { psi_server = run_psi_analytics(server_inputs, server_context); });

    client_thread.join();
    server_thread.join();

    ASSERT_EQ(psi_client, plain_intersection_size);
    ASSERT_EQ(psi_server, plain_intersection_size);
  }

  server_context.threshold = client_context.threshold = plain_intersection_size + 1;

  // threshold > intersection, should yield 0
  {
    std::thread client_thread(
        [&]() { psi_client = run_psi_analytics(client_inputs, client_context); });
    std::thread server_thread(
        [&]() { psi_server = run_psi_analytics(server_inputs, server_context); });

    client_thread.join();
    server_thread.join();

    ASSERT_EQ(psi_client, 0u);
    ASSERT_EQ(psi_server, 0u);
  }
}

void PsiAnalyticsSumTest(ENCRYPTO::PsiAnalyticsContext client_context,
                         ENCRYPTO::PsiAnalyticsContext server_context) {
  auto client_inputs = ENCRYPTO::GeneratePseudoRandomElements(client_context.neles, 15, 0);
  auto server_inputs = ENCRYPTO::GeneratePseudoRandomElements(client_context.neles, 15, 1);

  auto plain_intersection_size = ENCRYPTO::PlainIntersectionSize(client_inputs, server_inputs);
  assert(plain_intersection_size != 0);
  client_context.threshold = plain_intersection_size - 1;
  server_context.threshold = client_context.threshold;

  std::uint64_t psi_client, psi_server;

  {
    std::thread client_thread(
        [&]() { psi_client = run_psi_analytics(client_inputs, client_context); });
    std::thread server_thread(
        [&]() { psi_server = run_psi_analytics(server_inputs, server_context); });

    client_thread.join();
    server_thread.join();

    ASSERT_EQ(psi_client, plain_intersection_size);
    ASSERT_EQ(psi_server, plain_intersection_size);
  }

  server_context.threshold = client_context.threshold = plain_intersection_size + 1;

  {
    std::thread client_thread(
        [&]() { psi_client = run_psi_analytics(client_inputs, client_context); });
    std::thread server_thread(
        [&]() { psi_server = run_psi_analytics(server_inputs, server_context); });

    client_thread.join();
    server_thread.join();

    ASSERT_EQ(psi_client, plain_intersection_size);
    ASSERT_EQ(psi_server, plain_intersection_size);
  }
}

void PsiAnalyticsTest(std::size_t elem_bitlen, bool random, uint64_t neles, uint64_t polynomialsize,
                      uint64_t nmegabins) {
  auto client_context = CreateContext(CLIENT, neles, polynomialsize, nmegabins);
  auto server_context = CreateContext(SERVER, neles, polynomialsize, nmegabins);

  auto client_inputs =
      random ? ENCRYPTO::GeneratePseudoRandomElements(client_context.neles, elem_bitlen, 0)
             : ENCRYPTO::GenerateSequentialElements(client_context.neles);
  auto server_inputs =
      random ? ENCRYPTO::GeneratePseudoRandomElements(client_context.neles, elem_bitlen, 1)
             : ENCRYPTO::GenerateSequentialElements(client_context.neles);

  std::uint64_t psi_client, psi_server;

  std::thread client_thread(
      [&]() { psi_client = run_psi_analytics(client_inputs, client_context); });
  std::thread server_thread(
      [&]() { psi_server = run_psi_analytics(server_inputs, server_context); });

  client_thread.join();
  server_thread.join();

  auto plain_intersection_size = ENCRYPTO::PlainIntersectionSize(client_inputs, server_inputs);

  ASSERT_EQ(psi_client, plain_intersection_size);
  ASSERT_EQ(psi_server, plain_intersection_size);
}

TEST(PSI_ANALYTICS, pow_2_12_threshold) {
  for (auto i = 0ull; i < ITERATIONS; ++i) {
    // client's context
    ENCRYPTO::PsiAnalyticsContext cc{7777,  // port
                                     CLIENT,
                                     61,  // bitlength
                                     NELES_2_12,
                                     static_cast<uint64_t>(NELES_2_12 * 1.27f),
                                     0,  // # other party's elements
                                     1,  // # threads
                                     3,  // # hash functions
                                     1,  // threshold
                                     POLYNOMIALSIZE_2_12,
                                     POLYNOMIALSIZE_2_12 * sizeof(uint64_t),
                                     NMEGABINS_2_12,
                                     1.27f,  // epsilon
                                     "127.0.0.1",
                                     ENCRYPTO::PsiAnalyticsContext::THRESHOLD};

    // server's context
    ENCRYPTO::PsiAnalyticsContext sc{7777,  // port
                                     SERVER,
                                     61,  // bitlength
                                     NELES_2_12,
                                     static_cast<uint64_t>(NELES_2_12 * 1.27f),
                                     0,  // # other party's elements
                                     1,  // # threads
                                     3,  // # hash functions
                                     1,  // threshold
                                     POLYNOMIALSIZE_2_12,
                                     POLYNOMIALSIZE_2_12 * sizeof(uint64_t),
                                     NMEGABINS_2_12,
                                     1.27f,  // epsilon
                                     "127.0.0.1",
                                     ENCRYPTO::PsiAnalyticsContext::THRESHOLD};
    PsiAnalyticsThresholdTest(cc, sc);
  }
}

TEST(PSI_ANALYTICS, pow_2_12_sum_if_gt_threshold) {
  for (auto i = 0ull; i < ITERATIONS; ++i) {
    // client's context
    ENCRYPTO::PsiAnalyticsContext cc{7777,  // port
                                     CLIENT,
                                     61,  // bitlength
                                     NELES_2_12,
                                     static_cast<uint64_t>(NELES_2_12 * 1.27f),
                                     0,  // # other party's elements
                                     1,  // # threads
                                     3,  // # hash functions
                                     1,  // threshold
                                     POLYNOMIALSIZE_2_12,
                                     POLYNOMIALSIZE_2_12 * sizeof(uint64_t),
                                     NMEGABINS_2_12,
                                     1.27f,  // epsilon
                                     "127.0.0.1",
                                     ENCRYPTO::PsiAnalyticsContext::SUM_IF_GT_THRESHOLD};
    // server's context
    ENCRYPTO::PsiAnalyticsContext sc{7777,  // port
                                     SERVER,
                                     61,  // bitlength
                                     NELES_2_12,
                                     static_cast<uint64_t>(NELES_2_12 * 1.27f),
                                     0,  // # other party's elements
                                     1,  // # threads
                                     3,  // # hash functions
                                     1,  // threshold
                                     POLYNOMIALSIZE_2_12,
                                     POLYNOMIALSIZE_2_12 * sizeof(uint64_t),
                                     NMEGABINS_2_12,
                                     1.27f,  // epsilon
                                     "127.0.0.1",
                                     ENCRYPTO::PsiAnalyticsContext::SUM_IF_GT_THRESHOLD};
    PsiAnalyticsSumIfGtThresholdTest(cc, sc);
  }
}

TEST(PSI_ANALYTICS, pow_2_12_sum) {
  for (auto i = 0ull; i < ITERATIONS; ++i) {
    // client's context
    ENCRYPTO::PsiAnalyticsContext cc{7777,  // port
                                     CLIENT,
                                     61,  // bitlength
                                     NELES_2_12,
                                     static_cast<uint64_t>(NELES_2_12 * 1.27f),
                                     0,  // # other party's elements
                                     1,  // # threads
                                     3,  // # hash functions
                                     1,  // threshold
                                     POLYNOMIALSIZE_2_12,
                                     POLYNOMIALSIZE_2_12 * sizeof(uint64_t),
                                     NMEGABINS_2_12,
                                     1.27f,  // epsilon
                                     "127.0.0.1",
                                     ENCRYPTO::PsiAnalyticsContext::SUM};

    // server's context
    ENCRYPTO::PsiAnalyticsContext sc{7777,  // port
                                     SERVER,
                                     61,  // bitlength
                                     NELES_2_12,
                                     static_cast<uint64_t>(NELES_2_12 * 1.27f),
                                     0,  // # other party's elements
                                     1,  // # threads
                                     3,  // # hash functions
                                     1,  // threshold
                                     POLYNOMIALSIZE_2_12,
                                     POLYNOMIALSIZE_2_12 * sizeof(uint64_t),
                                     NMEGABINS_2_12,
                                     1.27f,  // epsilon
                                     "127.0.0.1",
                                     ENCRYPTO::PsiAnalyticsContext::SUM};
    PsiAnalyticsSumTest(cc, sc);
  }
}

TEST(PSI_ANALYTICS, pow_2_12_all_equal) {
  for (auto i = 0ull; i < ITERATIONS; ++i) {
    PsiAnalyticsTest(61, false, NELES_2_12, POLYNOMIALSIZE_2_12, NMEGABINS_2_12);
  }
}

TEST(PSI_ANALYTICS, pow_2_12_random) {
  for (auto i = 0ull; i < ITERATIONS; ++i) {
    PsiAnalyticsTest(15, true, NELES_2_12, POLYNOMIALSIZE_2_12, NMEGABINS_2_12);
  }
}

TEST(PSI_ANALYTICS, pow_2_12_probably_all_different) {
  for (auto i = 0ull; i < ITERATIONS; ++i) {
    PsiAnalyticsTest(61, true, NELES_2_12, POLYNOMIALSIZE_2_12, NMEGABINS_2_12);
  }
}

TEST(PSI_ANALYTICS, pow_2_16_all_equal) {
  for (auto i = 0ull; i < ITERATIONS; ++i) {
    PsiAnalyticsTest(61, false, NELES_2_16, POLYNOMIALSIZE_2_16, NMEGABINS_2_16);
  }
}

TEST(PSI_ANALYTICS, pow_2_16_random) {
  for (auto i = 0ull; i < ITERATIONS; ++i) {
    PsiAnalyticsTest(19, true, NELES_2_16, POLYNOMIALSIZE_2_16, NMEGABINS_2_16);
  }
}

TEST(PSI_ANALYTICS, pow_2_16_probably_all_different) {
  for (auto i = 0ull; i < ITERATIONS; ++i) {
    PsiAnalyticsTest(61, true, NELES_2_16, POLYNOMIALSIZE_2_16, NMEGABINS_2_16);
  }
}

TEST(PSI_ANALYTICS, pow_2_20_all_equal) {
  for (auto i = 0ull; i < ITERATIONS; ++i) {
    PsiAnalyticsTest(61, false, NELES_2_20, POLYNOMIALSIZE_2_20, NMEGABINS_2_20);
  }
}

TEST(PSI_ANALYTICS, pow_2_20_random) {
  for (auto i = 0ull; i < ITERATIONS; ++i) {
    PsiAnalyticsTest(23, true, NELES_2_20, POLYNOMIALSIZE_2_20, NMEGABINS_2_20);
  }
}

TEST(PSI_ANALYTICS, pow_2_20_probably_all_different) {
  for (auto i = 0ull; i < ITERATIONS; ++i) {
    PsiAnalyticsTest(61, true, NELES_2_20, POLYNOMIALSIZE_2_20, NMEGABINS_2_20);
  }
}

int main(int argc, char **argv) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}