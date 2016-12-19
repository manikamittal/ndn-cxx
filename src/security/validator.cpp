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
 *
 * @author Yingdi Yu <http://irl.cs.ucla.edu/~yingdi/>
 * @author Jeff Thompson <jefft0@remap.ucla.edu>
 */

#include "validator.hpp"
#include "../name-component.hpp"
#include "../util/crypto.hpp"
#include "../util/in-memory-storage-lru.hpp"

#include "v1/cryptopp.hpp"

namespace ndn {
namespace security {

static Oid SECP256R1("1.2.840.10045.3.1.7");
static Oid SECP384R1("1.3.132.0.34");

Validator::Validator(Face* face)
  : m_face(face)
{
    m_certificates = make_shared<util::InMemoryStorageLru>(); 
}

Validator::Validator(Face& face)
  : m_face(&face)
{  
    m_certificates = make_shared<util::InMemoryStorageLru>(); 
}

Validator::~Validator() = default;

void
Validator::validate(const Interest& interest,
                    const OnInterestValidated& onValidated,
                    const OnInterestValidationFailed& onValidationFailed,
                    int nSteps)
{
  std::vector<shared_ptr<ValidationRequest> > nextSteps;
  checkPolicy(interest, nSteps, onValidated, onValidationFailed, nextSteps);

  if (nextSteps.empty()) {
    // If there is no nextStep,
    // that means InterestPolicy has already been able to verify the Interest.
    // No more further processes.
    return;
  }

  OnFailure onFailure = bind(onValidationFailed, interest.shared_from_this(), _1);
  afterCheckPolicy(nextSteps, onFailure);
}

void
Validator::validate(const Data& data,
                    const OnDataValidated& onValidated,
                    const OnDataValidationFailed& onValidationFailed,
                    int nSteps)
{
  std::vector<shared_ptr<ValidationRequest> > nextSteps;
  checkPolicy(data, nSteps, onValidated, onValidationFailed, nextSteps);

  if (nextSteps.empty()) {
    // If there is no nextStep,
    // that means Data Policy has already been able to verify the Interest.
    // No more further processes.
    return;
  }

  OnFailure onFailure = bind(onValidationFailed, data.shared_from_this(), _1);
  checkKeyBundle(data.getName(), nextSteps, onFailure); 
}

void
Validator::onData(const Interest& interest,
                  const Data& data,
                  const shared_ptr<ValidationRequest>& nextStep)
{
  shared_ptr<const Data> certificateData = preCertificateValidation(data);

  if (!static_cast<bool>(certificateData))
    return nextStep->m_onDataValidationFailed(data.shared_from_this(),
                                              "Cannot decode cert: " + data.getName().toUri());

  validate(*certificateData,
           nextStep->m_onDataValidated, nextStep->m_onDataValidationFailed,
           nextStep->m_nSteps);
}

bool
Validator::verifySignature(const Data& data, const v1::PublicKey& key)
{
  if (!data.getSignature().hasKeyLocator())
    return false;

  return verifySignature(data.wireEncode().value(),
                         data.wireEncode().value_size() -
                         data.getSignature().getValue().size(),
                         data.getSignature(), key);
}

bool
Validator::verifySignature(const Interest& interest, const v1::PublicKey& key)
{
  const Name& name = interest.getName();

  if (name.size() < signed_interest::MIN_LENGTH_SIG_ONLY)
    return false;

  Signature sig;
  try {
    sig.setInfo(name[signed_interest::POS_SIG_INFO].blockFromValue());
    sig.setValue(name[signed_interest::POS_SIG_VALUE].blockFromValue());
  }
  catch (const tlv::Error&) {
    return false;
  }

  if (!sig.hasKeyLocator())
    return false;

  const Block& nameWire = name.wireEncode();
  return verifySignature(nameWire.value(),
                         nameWire.value_size() - name[signed_interest::POS_SIG_VALUE].size(),
                         sig, key);
}

bool
Validator::verifySignature(const uint8_t* buf,
                           const size_t size,
                           const Signature& sig,
                           const v1::PublicKey& key)
{
  try {
    using namespace CryptoPP;

    switch (sig.getType()) {
      case tlv::SignatureSha256WithRsa: {
        if (key.getKeyType() != KeyType::RSA)
          return false;

        RSA::PublicKey publicKey;
        ByteQueue queue;

        queue.Put(reinterpret_cast<const byte*>(key.get().buf()), key.get().size());
        publicKey.Load(queue);

        RSASS<PKCS1v15, SHA256>::Verifier verifier(publicKey);
        return verifier.VerifyMessage(buf, size,
                                      sig.getValue().value(), sig.getValue().value_size());
      }

      case tlv::SignatureSha256WithEcdsa: {
        if (key.getKeyType() != KeyType::EC)
          return false;

        ECDSA<ECP, SHA256>::PublicKey publicKey;
        ByteQueue queue;

        queue.Put(reinterpret_cast<const byte*>(key.get().buf()), key.get().size());
        publicKey.Load(queue);

        ECDSA<ECP, SHA256>::Verifier verifier(publicKey);

        uint32_t length = 0;
        StringSource src(key.get().buf(), key.get().size(), true);
        BERSequenceDecoder subjectPublicKeyInfo(src);
        {
          BERSequenceDecoder algorithmInfo(subjectPublicKeyInfo);
          {
            Oid algorithm;
            algorithm.decode(algorithmInfo);

            Oid curveId;
            curveId.decode(algorithmInfo);

            if (curveId == SECP256R1)
              length = 256;
            else if (curveId == SECP384R1)
              length = 384;
            else
              return false;
          }
        }

        switch (length) {
          case 256: {
            uint8_t buffer[64];
            size_t usedSize = DSAConvertSignatureFormat(buffer, sizeof(buffer), DSA_P1363,
                                                        sig.getValue().value(),
                                                        sig.getValue().value_size(),
                                                        DSA_DER);
            return verifier.VerifyMessage(buf, size, buffer, usedSize);
          }

          case 384: {
            uint8_t buffer[96];
            size_t usedSize = DSAConvertSignatureFormat(buffer, sizeof(buffer), DSA_P1363,
                                                        sig.getValue().value(),
                                                        sig.getValue().value_size(),
                                                        DSA_DER);
            return verifier.VerifyMessage(buf, size, buffer, usedSize);
          }

          default:
            return false;
        }
      }

      default:
        // Unsupported sig type
        return false;
    }
  }
  catch (const CryptoPP::Exception& e) {
    return false;
  }
}

bool
Validator::verifySignature(const uint8_t* buf, const size_t size, const DigestSha256& sig)
{
  try {
    ConstBufferPtr buffer = crypto::computeSha256Digest(buf, size);
    const Block& sigValue = sig.getValue();

    if (buffer != nullptr &&
        buffer->size() == sigValue.value_size() &&
        buffer->size() == crypto::SHA256_DIGEST_SIZE) {
      const uint8_t* p1 = buffer->buf();
      const uint8_t* p2 = sigValue.value();

      return 0 == memcmp(p1, p2, crypto::SHA256_DIGEST_SIZE);
    }
    else
      return false;
  }
  catch (const CryptoPP::Exception& e) {
    return false;
  }
}

void
Validator::onNack(const Interest& interest,
                  const lp::Nack& nack,
                  int remainingRetries,
                  const OnFailure& onFailure,
                  const shared_ptr<ValidationRequest>& validationRequest)
{
  if (remainingRetries > 0) {
    Interest newInterest = Interest(interest);
    newInterest.refreshNonce();

    //Express the same interest with different nonce and decremented remainingRetries.
    m_face->expressInterest(newInterest,
                            bind(&Validator::onData, this, _1, _2, validationRequest),
                            bind(&Validator::onNack, this, _1, _2,
                                 remainingRetries - 1, onFailure, validationRequest),
                            bind(&Validator::onTimeout, this, _1,
                                 remainingRetries - 1, onFailure, validationRequest));
  }
  else {
    onFailure("Cannot fetch cert: " + interest.getName().toUri());
  }
}

void
Validator::onTimeout(const Interest& interest,
                     int remainingRetries,
                     const OnFailure& onFailure,
                     const shared_ptr<ValidationRequest>& validationRequest)
{
  if (remainingRetries > 0) {
    Interest newInterest = Interest(interest);
    newInterest.refreshNonce();

    // Express the same interest with different nonce and decremented remainingRetries.
    m_face->expressInterest(newInterest,
                            bind(&Validator::onData, this, _1, _2, validationRequest),
                            bind(&Validator::onNack, this, _1, _2,
                                 remainingRetries - 1, onFailure, validationRequest),
                            bind(&Validator::onTimeout, this, _1,
                                 remainingRetries - 1, onFailure, validationRequest));
  }
  else {
    onFailure("Cannot fetch cert: " + interest.getName().toUri());
  }
}

void
Validator::onBundleData(const Interest& origInterest,
                        const Data& bundleData,  
                        bool isSegmentZeroExpected, 
                        const shared_ptr<ValidationRequest>& nextStep, 
                        const std::vector<shared_ptr<ValidationRequest>>& nextSteps,
                        const OnFailure& onFailure)
{
  name::Component currentSegment = bundleData.getName().get(-1);

  if (isSegmentZeroExpected && currentSegment.toSegment() != 0) {
    // fetch segment zero
    fetchNextBundleSegment(origInterest, bundleData.getName(), nextStep, 
                           0, nextSteps, onFailure);
  }
  else {
    Block bundleContent = bundleData.getContent();     
    bundleContent.parse(); 
    Block::element_const_iterator bundleIterator = bundleContent.elements_begin(); 

    // store certificates in memory 
    while (bundleIterator != bundleContent.elements_end()) 
    {
      shared_ptr<Certificate> certificate = make_shared<Certificate>(*bundleIterator);
      m_certificates->insert(*certificate); 
      ++bundleIterator; 
    }

    // fetch next segment if applicable
    const name::Component& finalBlockId = bundleData.getMetaInfo().getFinalBlockId();
    if (finalBlockId.empty() || (finalBlockId > currentSegment)) {
      fetchNextBundleSegment(origInterest, bundleData.getName(), nextStep, 
                             currentSegment.toSegment() + 1, nextSteps, onFailure);
    }
    else {
      util::InMemoryStorageLru::const_iterator certificateIterator = m_certificates->begin();
      Certificate firstCert = Certificate(*certificateIterator);

      onData(nextStep->m_interest, firstCert, nextStep);
    }
  }
}

void
Validator::onBundleNack(const Interest& interest,
                        const lp::Nack& nack, 
                        const std::vector<shared_ptr<ValidationRequest>>& nextSteps,
                        const OnFailure& onFailure)
{
  afterCheckPolicy(nextSteps, onFailure);
}

void
Validator::onBundleTimeout(const Interest& interest, 
                           const std::vector<shared_ptr<ValidationRequest>>& nextSteps,
                           const OnFailure& onFailure)
{
  afterCheckPolicy(nextSteps, onFailure);
}

void
Validator::checkKeyBundle(const Name& dataName,
                          const std::vector<shared_ptr<ValidationRequest>>& nextSteps,
                          const OnFailure& onFailure)
{
  shared_ptr<ValidationRequest> nextStep = nextSteps.front();
  shared_ptr<const Data> certificate =  m_certificates->find(nextStep->m_interest); 

  if (certificate == nullptr) {
    Name bundleName = deriveBundleName(data.getName()); 
    bundleName
      .append("BUNDLE"); 

    Interest bundleInterest = Interest(bundleName);
    bundleInterest.setInterestLifetime(time::milliseconds(100000));
    bundleInterest.setMustBeFresh(true);
    bundleInterest.setChildSelector(1); 

    fetchFirstBundleSegment(bundleInterest, nextStep, nextSteps, onFailure); 
  }
  else {
    // if certificate is present in memory 
    onData(nextStep->m_interest, *certificate, nextStep);  
  }
}

Name 
Validator::deriveBundleName(const Name& name) 
{
  name::Component lastComponent = name.get(- 1); 

  Name bundleName = name; 
  if(lastComponent.isImplicitSha256Digest()) {
    if(name.get(-2).isSegment()) {
      bundleName = name.getPrefix(-2); 
    }
    else {
      bundleName = name.getPrefix(-1); 
    }
  }
  else if(lastComponent.isSegment()) {
    bundleName = name.getPrefix(-1); 
  }
  
  return bundleName; 
}

void 
Validator::fetchFirstBundleSegment(const Interest& interest, 
                                   const shared_ptr<ValidationRequest>& nextStep, 
                                   const std::vector<shared_ptr<ValidationRequest>>& nextSteps,
                                   const OnFailure& onFailure)
{
  if (m_face == nullptr) {
    onFailure("Require more information to validate the packet!");
    return;
  }

  m_face->expressInterest(interest, 
                          bind(&Validator::onBundleData, this,  _1, _2, 
                               true, nextStep, nextSteps, onFailure), 
                          bind(&Validator::onBundleNack, this, _1, _2, 
                               nextSteps, onFailure), 
                          bind(&Validator::onBundleTimeout, this, _1, 
                               nextSteps, onFailure)); 
}

void 
Validator::fetchNextBundleSegment(const Interest& origInterest, 
                                  const Name& bundleDataName, 
                                  const shared_ptr<ValidationRequest>& nextStep, 
                                  uint64_t segmentNo, 
                                  const std::vector<shared_ptr<ValidationRequest>>& nextSteps,
                                  const OnFailure& onFailure)
{
  Interest interest(origInterest); // to preserve any selectors
  interest.refreshNonce();
  interest.setChildSelector(0);
  interest.setMustBeFresh(false);
  interest.setName(bundleDataName.getPrefix(-1).appendSegment(segmentNo));

  m_face->expressInterest(interest,
                         bind(&Validator::onBundleData, this,  _1, _2, 
                              true, nextStep, nextSteps, onFailure), 
                         bind(&Validator::onBundleNack, this, _1, _2, 
                              nextSteps, onFailure), 
                         bind(&Validator::onBundleTimeout, this, _1, 
                              nextSteps, onFailure)); 
}

void
Validator::afterCheckPolicy(const std::vector<shared_ptr<ValidationRequest>>& nextSteps,
                            const OnFailure& onFailure)
{
  if (m_face == nullptr) {
    onFailure("Require more information to validate the packet!");
    return;
  }

  for (shared_ptr<ValidationRequest> step : nextSteps) {
    m_face->expressInterest(step->m_interest,
                            bind(&Validator::onData, this, _1, _2, step),
                            bind(&Validator::onNack, this, _1, _2,
                                 step->m_nRetries, onFailure, step),
                            bind(&Validator::onTimeout,
                                 this, _1, step->m_nRetries,
                                 onFailure,
                                 step));
  }
}

} // namespace security
} // namespace ndn
