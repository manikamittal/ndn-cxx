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

#include "bundle-state.hpp"
#include "security/signing-helpers.hpp"

namespace ndn {
namespace util {

BundleState::BundleState(const Name& signingKeyName)
  : m_signingKeyName(signingKeyName)
{
}

BundleState::~BundleState()
{
}

size_t
BundleState::getDepth() const
{
  return m_certificateChain.size();
}

bool
BundleState::hasSeenCertificateName(const Name& certName)
{
  return !m_seenCertificateNames.insert(certName).second;
}

void
BundleState::addCertificate(const security::v2::Certificate& cert)
{
  m_certificateChain.push_back(cert);
}

void
BundleState::createCertBundle(const Name& bundleInterestName)
{
  Name bundleName = bundleInterestName;
  bundleName.appendVersion();

  uint64_t segmentNumber = 0;
  Block certBundle = Block(tlv::Content);

  for (auto it = m_certificateChain.begin(); it != m_certificateChain.end(); ++it) {
    const auto& cert = *it;
    certBundle.encode();

    if (certBundle.size() + cert.getContent().size() >= MAX_NDN_PACKET_SIZE) {
      createBundleSegment(bundleName, segmentNumber, certBundle, false);
      certBundle = Block(tlv::Content);
      ++segmentNumber;
    }
    certBundle.parse();
    certBundle.push_back(cert.wireEncode());
  }
  createBundleSegment(bundleName, segmentNumber, certBundle, true);
}

void
BundleState::createBundleSegment(const Name& bundleName, const uint64_t segmentNumber,
                                 const Block& bundleSegmentContent, bool isFinalSegment)
{
  Name fullBundleName = bundleName;
  fullBundleName.appendSegment(segmentNumber);

  shared_ptr<Data> bundleSegment = make_shared<Data>();
  bundleSegment->setName(fullBundleName);
  bundleSegment->setFreshnessPeriod(time::seconds(10));
  bundleSegment->setContent(bundleSegmentContent);

  if (isFinalSegment) {
    bundleSegment->setFinalBlockId(fullBundleName.get(-1));
  }

  m_keyChain.sign(*bundleSegment, signingWithSha256());
  m_bundleSegments.push_back(bundleSegment);
}

} // namespace util
} // namespace ndn
