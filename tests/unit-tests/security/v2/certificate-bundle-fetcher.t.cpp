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

#include "security/v2/certificate-bundle-fetcher.hpp"
#include "security/v2/validation-policy-simple-hierarchy.hpp"
#include "util/regex/regex-pattern-list-matcher.hpp"
#include "lp/nack.hpp"

#include "boost-test.hpp"
#include "validator-fixture.hpp"

namespace ndn {
namespace security {
namespace v2 {
namespace tests {

using namespace ndn::tests;

BOOST_AUTO_TEST_SUITE(Security)
BOOST_AUTO_TEST_SUITE(V2)
BOOST_AUTO_TEST_SUITE(TestCertificateBundleFetcher)

class Bundle
{
};

class Cert
{
};

class Timeout
{
};

class Nack
{
};

template<class Response>
class CertificateBundleFetcherFixture : public HierarchicalValidatorFixture<ValidationPolicySimpleHierarchy,
                                                                            CertificateBundleFetcher>
{
public:
  CertificateBundleFetcherFixture()
    : data("/Security/V2/ValidatorFixture/Sub1/Sub3/Data")
  {
    subSubIdentity = addSubCertificate("/Security/V2/ValidatorFixture/Sub1/Sub3", subIdentity);
    cache.insert(subSubIdentity.getDefaultKey().getDefaultCertificate());

    m_keyChain.sign(data, signingByIdentity(subSubIdentity));

    processInterest = [this] (const Interest& interest) {
      // check if the interest is for Bundle or individual certificates
      shared_ptr<RegexPatternListMatcher> regexMatcher = make_shared<RegexPatternListMatcher>("<>*<BUNDLE><>*", nullptr);
      if (regexMatcher->match(interest.getName(), 0, interest.getName().size())) {
        makeResponse(interest);
      }
      else {
        makeCertResponse(interest);
      }
    };
  }

  void
  makeResponse(const Interest& interest);
  void
  makeCertResponse(const Interest& interest);

public:
  Data data;
  Identity subSubIdentity;
};

template<>
void
CertificateBundleFetcherFixture<Bundle>::makeResponse(const Interest& interest)
{

  Block certList = Block(tlv::Content);
  Name bundleName(interest.getName());

  if (!bundleName.get(-1).isSegment() || bundleName.get(-1).toSegment() == 0)
  {
    Block subSubCert = subSubIdentity.getDefaultKey().getDefaultCertificate().wireEncode();
    certList.push_back(subSubCert);

    if(!bundleName.get(-1).isSegment())
    {
      bundleName
        .appendVersion()
        .appendSegment(0);
    }
  }
  else {
    Block subCert = subIdentity.getDefaultKey().getDefaultCertificate().wireEncode();
    Block anchor = identity.getDefaultKey().getDefaultCertificate().wireEncode();
    certList.push_back(subCert);
    certList.push_back(anchor);
  }

  shared_ptr<Data> certBundle = make_shared<Data>();
  certBundle->setName(bundleName);
  certBundle->setFreshnessPeriod(time::seconds(100));
  certBundle->setContent(certList);

  if (bundleName.get(-1).toSegment() != 0)
    certBundle->setFinalBlockId(bundleName.get(-1));

  m_keyChain.sign(*certBundle, security::SigningInfo(security::SigningInfo::SIGNER_TYPE_SHA256));

  face.receive(*certBundle);
}

template<>
void
CertificateBundleFetcherFixture<Timeout>::makeResponse(const Interest& interest)
{
  this->advanceClocks(time::seconds(200));
}

template<>
void
CertificateBundleFetcherFixture<Nack>::makeResponse(const Interest& interest)
{
  lp::Nack nack(interest);
  nack.setHeader(lp::NackHeader().setReason(lp::NackReason::NO_ROUTE));
  face.receive(nack);
}

template<class Response>
void
CertificateBundleFetcherFixture<Response>::makeCertResponse(const Interest& interest)
{
  auto cert = cache.find(interest);
  if (cert == nullptr) {
    return;
  }
  face.receive(*cert);
}

BOOST_FIXTURE_TEST_CASE(ValidateSuccessWithBundle, CertificateBundleFetcherFixture<Bundle>)
{
  VALIDATE_SUCCESS(this->data, "Should get accepted, as interest brings the bundle segments");
  BOOST_CHECK_EQUAL(this->face.sentInterests.size(), 2); // produced bundle has 2 segments
}

using SuccessWithoutBundle = boost::mpl::vector<Nack, Timeout>;

BOOST_FIXTURE_TEST_CASE_TEMPLATE(ValidateSuccessWithoutBundle, T, SuccessWithoutBundle, CertificateBundleFetcherFixture<T>)
{
  VALIDATE_SUCCESS(this->data, "Should get accepted, as interest brings the certs");
  BOOST_CHECK_GT(this->face.sentInterests.size(), 2); // since interest for Bundle fails, each cert is retrieved
}

BOOST_AUTO_TEST_SUITE_END() // TestCertificateBundleFetcher
BOOST_AUTO_TEST_SUITE_END() // V2
BOOST_AUTO_TEST_SUITE_END() // Security

} // namespace tests
} // namespace v2
} // namespace security
} // namespace ndn
