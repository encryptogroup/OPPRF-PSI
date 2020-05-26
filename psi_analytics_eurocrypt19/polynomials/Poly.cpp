// \author Avishay Yanay
// \organization Bar-Ilan University
// \email ay.yanay@gmail.com
//
// MIT License
//
// Copyright (c) 2018 AvishayYanay
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#include "Poly.h"

// coef[i] (beginning from 0)is multiplied by x^i
void Poly::evalMersenne(ZpMersenneLongElement& Y, const std::vector<ZpMersenneLongElement>& coeff,
                        ZpMersenneLongElement X)
// does a Horner evaluation
{
  ZpMersenneLongElement acc(0);

  for (int64_t i = coeff.size() - 1; i >= 0; i--) {
    acc = acc * X;         // mul(acc, acc, a);
    acc = acc + coeff.at(i);  // add(acc, acc, f.rep[i]);
    //        cout << "coef["<< i << "]: " << coeff[i] << endl;
  }

  Y = acc;
}

void Poly::interpolateMersenne(std::vector<ZpMersenneLongElement>& coeff,
                               const std::vector<ZpMersenneLongElement>& X,
                               std::vector<ZpMersenneLongElement>& Y) {
  int64_t m = X.size();
  if (Y.size() != X.size()) std::cout << "interpolate: vector length mismatch" << std::endl;

  ZpMersenneLongElement one(1);
  ZpMersenneLongElement zero(0);

  ZpMersenneLongElement p(ZpMersenneLongElement::p);

  std::vector<ZpMersenneLongElement> prod;
  prod = X;

  ZpMersenneLongElement t1, t2;

  int64_t k, i;

  std::vector<ZpMersenneLongElement> res;
  res.resize(m);

  for (k = 0; k < m; k++) {
    const ZpMersenneLongElement& aa = X[k];

    t1 = 1;
    for (i = k - 1; i >= 0; i--) {
      t1 = t1 * aa;       // mul(t1, t1, aa);
      t1 = t1 + prod[i];  // add(t1, t1, prod[i]);
    }

    t2 = 0;  // clear(t2);
    for (i = k - 1; i >= 0; i--) {
      t2 = t2 * aa;      // mul(t2, t2, aa);
      t2 = t2 + res[i];  // add(t2, t2, res[i]);
    }

    t1 = one / t1;   // inv(t1, t1);
    t2 = Y[k] - t2;  // sub(t2, b[k], t2);
    t1 = t1 * t2;    // mul(t1, t1, t2);

    for (i = 0; i < k; i++) {
      t2 = prod[i] * t1;     // mul(t2, prod[i], t1);
      res[i] = res[i] + t2;  // add(res[i], res[i], t2);
    }

    res[k] = t1;

    if (k < m - 1) {
      if (k == 0)
        prod[0] = p - prod[0];  // sub(prod[0], to_ZZ_p(ZZ_pInfo->p),prod[0]);//sub(prod[0],
                                // ZZ_p::modulus(), prod[0]);//negate(prod[0], prod[0]);
      else {
        t1 = p - X[k];               // sub(t1, to_ZZ_p(ZZ_pInfo->p),a[k]);//negate(t1, a[k]);
        prod[k] = t1 + prod[k - 1];  // add(prod[k], t1, prod[k-1]);
        for (i = k - 1; i >= 1; i--) {
          t2 = prod[i] * t1;           // mul(t2, prod[i], t1);
          prod[i] = t2 + prod[i - 1];  // add(prod[i], t2, prod[i-1]);
        }
        prod[0] = prod[0] * t1;  // mul(prod[0], prod[0], t1);
      }
    }
  }

  while (m > 0 && !(res[m - 1] != zero)) m--;
  res.resize(m);

  coeff = res;
}
