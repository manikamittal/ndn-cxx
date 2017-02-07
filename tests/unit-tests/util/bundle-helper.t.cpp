/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2013-2017 Regents of the University of California.
 *
 * This file is part of ndn-cxx library (NDN C++ library with eXperimental eXtensions).
 *
 * ndn-cxx library is free software: you can redistribute it and/or modify it under the
 * terms of the GNU Lesser General Public License as published by the Free Software
 * Foundation, either version 3 of the License, or (at your option) any later version.
 *
 * ndn-cxx library is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
 * PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received copies of the GNU General Public License and GNU Lesser
 * General Public License along with ndn-cxx, e.g., in COPYING.md file.  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 * See AUTHORS.md for complete list of ndn-cxx authors and contributors.
 */

#include "security/v2/certificate-cache.hpp"
#include "util/bundle-helper.hpp"
#include "util/dummy-client-face.hpp"

#include "../identity-management-time-fixture.hpp"

#include "boost-test.hpp"

namespace ndn {
namespace util {
namespace tests {

using namespace ndn::tests;

BOOST_AUTO_TEST_SUITE(Util)
BOOST_AUTO_TEST_SUITE(TestBundleHelper)

class CertificateBundleFixture : public ndn::tests::IdentityManagementTimeFixture
{
public:
  CertificateBundleFixture()
    : face(io, {true, true})
    , bundleHelper(face)
    , cache(time::days(100))
  {
    processInterest = [this] (const Interest& interest) {
      auto cert = cache.find(interest);
      if (cert != nullptr) {
        face.receive(*cert);
      }
    };
  }

  virtual
  ~CertificateBundleFixture() = default;

  void
  beginBundleCreation(const Name& identityName)
  {
    bundleState = this->bundleHelper.beginBundleCreation(identityName);
    mockNetworkOperations();
  }

  void
  mockNetworkOperations()
  {
    util::signal::ScopedConnection connection = face.onSendInterest.connect([this] (const Interest& interest) {
        if (processInterest != nullptr) {
          io.post(bind(processInterest, interest));
        }
      });
    advanceClocks(time::milliseconds(250), 200);
  }

public:
  DummyClientFace face;
  std::function<void(const Interest& interest)> processInterest;
  BundleHelper bundleHelper;
  security::v2::CertificateCache cache;
  shared_ptr<BundleState> bundleState;
};


class CertificateBundleHelperFixture : public CertificateBundleFixture
{
public:
  CertificateBundleHelperFixture()
    : data("/Security/V2/ValidatorFixture/Sub1/Sub3/Data")
  {
    identity = this->addIdentity("/Security/V2/ValidatorFixture");
    subIdentity = this->addSubCertificate("/Security/V2/ValidatorFixture/Sub1", identity);
    subSubIdentity = this->addSubCertificate("/Security/V2/ValidatorFixture/Sub1/Sub3", subIdentity);

    this->cache.insert(identity.getDefaultKey().getDefaultCertificate());
    this->cache.insert(subIdentity.getDefaultKey().getDefaultCertificate());
    this->cache.insert(subSubIdentity.getDefaultKey().getDefaultCertificate());

    m_keyChain.sign(data, signingByIdentity(subSubIdentity));
  }

public:
  Data data;
  security::Identity identity;
  security::Identity subIdentity;
  security::Identity subSubIdentity;
};

BOOST_FIXTURE_TEST_CASE(BundleHelperTestCase, CertificateBundleHelperFixture)
{
  std::vector<shared_ptr<const Data>> bundleSegments;

  this->beginBundleCreation(this->subSubIdentity.getName());
  this->advanceClocks(time::seconds(20));

  bundleSegments = bundleHelper.getBundle(this->data.getName(), bundleState);
  BOOST_CHECK_EQUAL(bundleSegments.size(), 1);

  shared_ptr<const Data> firstBundleSegment = bundleSegments.front();
  Block bundleContent = firstBundleSegment->getContent();
  bundleContent.parse();
  BOOST_CHECK_EQUAL(bundleContent.elements_size(), 3);
}

BOOST_AUTO_TEST_SUITE_END() // TestBundleHelper
BOOST_AUTO_TEST_SUITE_END() // Util

} // namespace tests
} // namespace util
} // namespace ndn
