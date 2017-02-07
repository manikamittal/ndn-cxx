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

#ifndef NDN_UTIL_BUNDLE_HELPER_HPP
#define NDN_UTIL_BUNDLE_HELPER_HPP

#include "../face.hpp"
#include "bundle-state.hpp"

namespace ndn {
namespace util {

/**
 * @brief provides interface for certificate bundle creation
 */
class BundleHelper
{
public:
  explicit
  BundleHelper(Face& face);

  ~BundleHelper();

  /**
   * @brief Set the maximum size of certificate bundle
   */
  void
  setMaxBundleSize(size_t bundleSize);

  /**
   * @return The maximum size of certificate bundle
   */
  size_t
  getMaxBundleSize() const;

  /*
   * @brief Begins bundle creation process by collecting certificates
   *
   * This method creates a state for a new bundle associated with
   * the @p signing key name. It initiates the process of collecting the
   * certificate chain and returns the current bundle state. This method
   * does NOT return the bundle segments itself. The producer needs to call
   * getBundle to get the actual bundle segments.
   */
  shared_ptr<BundleState>
  beginBundleCreation(const Name& signingKeyName);

  /*
   * @brief Refreshes the list of certificates in a bundle
   *
   * This method does NOT return the bundle segments itself. The producer
   * needs to call getBundle to get the actual bundle segments.
   */
  void
  refreshBundle(shared_ptr<BundleState>& bundleState);

  /*
   * @brief Returns the bundle segments associated with the @p state
   */
  std::vector<shared_ptr<const Data>>&
  getBundle(const Name& bundleInterestName, shared_ptr<BundleState>& bundleState);

private:
  void
  fetchCertificate(const Name& certToFetch, shared_ptr<BundleState>& bundleState);

  void
  onCertData(const Interest& interest, const Data& certData, shared_ptr<BundleState>& bundleState);

  void
  onCertNack(const Interest& interest, const lp::Nack& nack);

  void
  onCertTimeout(const Interest& interest);

private:
  Face& m_face;
  size_t m_maxBundleSize;
};

} // namespace util
} // namespace ndn

#endif // NDN_UTIL_BUNDLE_HELPER_HPP