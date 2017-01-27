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

#ifndef NDN_SECURITY_V2_CERTIFICATE_BUNDLE_FETCHER_HPP
#define NDN_SECURITY_V2_CERTIFICATE_BUNDLE_FETCHER_HPP

#include "certificate-fetcher-from-network.hpp"

namespace ndn {
namespace security {
namespace v2 {

/**
 * @brief Fetch certificate bundle from the network
 */
class CertificateBundleFetcher : public CertificateFetcherFromNetwork
{
public:
  explicit
  CertificateBundleFetcher(Face& face);

  /**
   * @brief Set the lifetime of certificate bundle interest
   */
  void
  setBundleInterestLifetime(time::seconds time);

  /**
   * @return The lifetime of certificate bundle interest
   */
  time::seconds
  getBundleInterestLifetime() const;

protected:
  void
  doFetch(const shared_ptr<CertificateRequest>& certRequest, const shared_ptr<ValidationState>& state,
          const ValidationContinuation& continueValidation) override;

private:
  /**
   * @brief Fetches the first bundle segment.
   */
  void
  fetchFirstBundleSegment(const Name& bundleNamePrefix,
                          const shared_ptr<CertificateRequest>& certRequest,
                          const shared_ptr<ValidationState>& state,
                          const ValidationContinuation& continueValidation);

  /**
   * @brief Fetches the specified bundle segment.
   */
  void
  fetchNextBundleSegment(const Name& fullBundleName, const name::Component& segmentNo,
                         const shared_ptr<CertificateRequest>& certRequest,
                         const shared_ptr<ValidationState>& state,
                         const ValidationContinuation& continueValidation);

  /**
   * @brief Derive bundle name from data name.
   */
  Name
  deriveBundleName(const Name& name);

  /**
   * @brief Callback invoked when certificate bundle is retrieved.
   */
  void
  dataCallback(const Data& data, bool isSegmentZeroExpected,
               const shared_ptr<CertificateRequest>& certRequest, const shared_ptr<ValidationState>& state,
               const ValidationContinuation& continueValidation);

  /**
   * @brief Callback invoked when interest for fetching certificate bundle gets NACKed.
   */
  void
  nackCallback(const lp::Nack& nack,
               const shared_ptr<CertificateRequest>& certRequest, const shared_ptr<ValidationState>& state,
               const ValidationContinuation& continueValidation, const Name& bundleName);

  /**
   * @brief Callback invoked when interest for fetching certificate times out.
   */
  void
  timeoutCallback(const shared_ptr<CertificateRequest>& certRequest, const shared_ptr<ValidationState>& state,
                  const ValidationContinuation& continueValidation, const Name& bundleName);

private:
  using BundleNameTag = SimpleTag<Name, 1000>;
  using FinalBlockIdTag = SimpleTag<name::Component, 1001>;
  time::seconds m_bundleInterestLifetime;
};

} // namespace v2
} // namespace security
} // namespace ndn

#endif // NDN_SECURITY_V2_CERTIFICATE_BUNDLE_FETCHER_HPP
