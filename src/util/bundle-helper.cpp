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

#include "bundle-helper.hpp"
#include "logger.hpp"

namespace ndn {
namespace util {

NDN_LOG_INIT(ndn.util.BundleHelper);

BundleHelper::BundleHelper(Face& face)
  : m_face(face)
  , m_maxBundleSize(25)
{
}

BundleHelper::~BundleHelper() = default;

void
BundleHelper::setMaxBundleSize(size_t bundleSize)
{
  m_maxBundleSize = bundleSize;
}

size_t
BundleHelper::getMaxBundleSize() const
{
  return m_maxBundleSize;
}

shared_ptr<BundleState>
BundleHelper::beginBundleCreation(const Name& signingKeyName)
{
  auto bundleState = make_shared<BundleState>(signingKeyName);
  fetchCertificate(signingKeyName, bundleState);
  return bundleState;
}

void
BundleHelper::refreshBundle(shared_ptr<BundleState>& bundleState)
{
  if (bundleState == nullptr) {
    NDN_LOG_DEBUG("Invalid Bundle State while refreshing certificate bundle");
    return;
  }
  fetchCertificate(bundleState->m_signingKeyName, bundleState);
}

std::vector<shared_ptr<const Data>>&
BundleHelper::getBundle(const Name& bundleInterestName, shared_ptr<BundleState>& bundleState)
{
  bundleState->createCertBundle(bundleInterestName);
  return bundleState->m_bundleSegments;
}

void
BundleHelper::fetchCertificate(const Name& certToFetch, shared_ptr<BundleState>& bundleState)
{
  if (bundleState->getDepth() >= m_maxBundleSize ||
      bundleState->hasSeenCertificateName(certToFetch)) {
    return;
  }

  Interest certInterest = Interest(certToFetch);
  certInterest.setInterestLifetime(time::seconds(1));
  certInterest.setMustBeFresh(true);

  m_face.expressInterest(certInterest,
                         bind(&BundleHelper::onCertData, this,  _1, _2, bundleState),
                         bind(&BundleHelper::onCertNack, this, _1, _2),
                         bind(&BundleHelper::onCertTimeout, this, _1));
}

void
BundleHelper::onCertData(const Interest& interest, const Data& certData,
                         shared_ptr<BundleState>& bundleState)
{
  security::v2::Certificate cert;
  try {
    cert = security::v2::Certificate(certData);
    bundleState->addCertificate(cert);
  }
  catch (const tlv::Error& e) {
    return;
  }

  const Signature& signature = cert.getSignature();
  if (!signature.hasKeyLocator() ||
      signature.getKeyLocator().getType() != KeyLocator::KeyLocator_Name) {
    return;
  }

  Name keyLocatorName = cert.getSignature().getKeyLocator().getName();
  fetchCertificate(keyLocatorName, bundleState);
}

void
BundleHelper::onCertNack(const Interest& interest, const lp::Nack& nack)
{
  // do nothing
}

void
BundleHelper::onCertTimeout(const Interest& interest)
{
  // do nothing
}

} // namespace util
} // namespace ndn
