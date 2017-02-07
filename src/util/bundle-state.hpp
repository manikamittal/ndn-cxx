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

#ifndef NDN_UTIL_BUNDLE_STATE_HPP
#define NDN_UTIL_BUNDLE_STATE_HPP

#include "security/key-chain.hpp"

#include <unordered_set>
#include <list>

namespace ndn {
namespace util {

class BundleHelper;

/**
 * @brief Certificate Bundle state
 *
 * One instance of the bundle state is kept for the creation of the whole certificate
 * bundle.
 *
 * The state collects the certificate chain starting from the key locator name of the
 * target data packet. The state will contain the current version of the Bundle that
 * has been created thus far.
 */
class BundleState
{
public:
  /**
   * @brief Create Bundle state
   */
  BundleState(const Name& signingKeyName);

  virtual
  ~BundleState();

  /**
   * @return Depth of certificate chain
   */
  size_t
  getDepth() const;

  /**
   * @brief Check if @p certName has been previously seen and record the supplied name
   */
  bool
  hasSeenCertificateName(const Name& certName);

  /**
   * @brief Add @p cert to the back of the certificate chain
   */
  void
  addCertificate(const security::v2::Certificate& cert);

private: // To be used only by the Bundle Helper
  /**
   * @brief Creates the complete certificate bundle with @p bundle interest name
   */
  void
  createCertBundle(const Name& bundleInterestName);

  /**
   * @brief Creates a single bundle segment
   */
  void
  createBundleSegment(const Name& bundleName, const uint64_t segmentNumber,
                      const Block& bundleSegmentContent, bool isFinalSegment);

private:
  const Name& m_signingKeyName;

  std::vector<shared_ptr<const Data>> m_bundleSegments;
  std::unordered_set<Name> m_seenCertificateNames;
  std::vector<security::v2::Certificate> m_certificateChain;

  KeyChain m_keyChain;
  friend class BundleHelper;
};

} // namespace util
} // namespace ndn

#endif // NDN_UTIL_BUNDLE_STATE_HPP
