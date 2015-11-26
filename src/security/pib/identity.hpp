/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2013-2016 Regents of the University of California.
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

#ifndef NDN_SECURITY_PIB_IDENTITY_HPP
#define NDN_SECURITY_PIB_IDENTITY_HPP

#include "key-container.hpp"

namespace ndn {
namespace security {

class KeyChain;

namespace pib {

namespace detail {
class IdentityImpl;
} // namespace detail

/**
 * @brief A frontend handle of an Identity
 *
 * Identity is at the top level in PIB's Identity-Key-Certificate hierarchy.
 * An identity has a Name, and contains one or more keys, one of which is set
 * as the default key of this identity.  Properties of a key can be accessed
 * after obtaining a Key object.
 *
 * @throw PibImpl::Error when underlying implementation has non-semantic error.
 */
class Identity
{
public:
  friend class KeyChain;

public:
  /**
   * @brief Default Constructor
   *
   * Identity created using this default constructor is just a place holder.
   * It can obtain an actual instance from Pib::getIdentity(...).  A typical
   * usage would be for exception handling:
   *
   *   Identity id;
   *   try {
   *     id = pib.getIdentity(...);
   *   }
   *   catch (Pib::Error&) {
   *     ...
   *   }
   *
   * An Identity instance created using the constructor is invalid. Calling a
   * member method on an invalid Identity instance may cause an std::domain_error.
   */
  Identity();

  /**
   * @brief Create an Identity with a backend implementation @p impl.
   *
   * This method should only be used by IdentityContainer.
   */
  explicit
  Identity(weak_ptr<detail::IdentityImpl> impl);

  /// @brief Get the name of the identity.
  const Name&
  getName() const;

  /**
   * @brief Get a key with id @p keyName.
   * @throw std::invalid_argument if @p keyName does not match identity
   * @throw Pib::Error if the key does not exist.
   */
  Key
  getKey(const Name& keyName) const;

  /// @brief Get all the keys for this identity.
  const KeyContainer&
  getKeys() const;

  /**
   * @brief Get the default key for this Identity.
   * @throw Pib::Error if the default key does not exist.
   */
  const Key&
  getDefaultKey() const;

  /// @brief Check if the Identity instance is valid
  operator bool() const;

  /// @brief Check if the Identity instance is invalid
  bool
  operator!() const;

NDN_CXX_PUBLIC_WITH_TESTS_ELSE_PRIVATE: // write operations should be private
  /**
   * @brief Add a @p key of @p keyLen bytes with @p keyName (in PKCS#8 format).
   * @return the handle of added key
   * @throw std::invalid_argument if key name does not match identity
   * @throw Pib::Error if a key with the same name already exists
   */
  Key
  addKey(const uint8_t* key, size_t keyLen, const Name& keyName);

  /**
   * @brief Remove a key with @p keyName
   * @throw std::invalid_argument if @p keyName does not match identity
   */
  void
  removeKey(const Name& keyName);


  /**
   * @brief Set an existing key with @p keyName as the default key.
   * @throw std::invalid_argument if @p keyName does not match identity
   * @throw Pib::Error if the key does not exist.
   * @return The default key
   */
  const Key&
  setDefaultKey(const Name& keyName);

  /**
   * @brief Add a @p key of @p keyLen bytes with @p keyName and set it as the default key
   * @throw std::invalid_argument if @p keyName does not match identity
   * @throw Pib::Error if the key with the same name already exists.
   * @return the default key
   */
  const Key&
  setDefaultKey(const uint8_t* key, size_t keyLen, const Name& keyName);

private:
  /**
   * @brief Check the validity of the instance
   * @return a shared_ptr when the instance is valid
   * @throw std::domain_error when the instance is invalid
   */
  shared_ptr<detail::IdentityImpl>
  lock() const;

private:
  weak_ptr<detail::IdentityImpl> m_impl;
};

} // namespace pib

using pib::Identity;

} // namespace security
} // namespace ndn

#endif // NDN_SECURITY_PIB_IDENTITY_HPP
