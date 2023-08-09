/**
 * Copyright (c) 2018-2023, BOTLabs GmbH.
 *
 * This source code is licensed under the BSD 4-Clause "Original" license
 * found in the LICENSE file in the root directory of this source tree.
 */

import { Attestation, Claim, Credential, CType, Quote } from '@kiltprotocol/core'
import { DataUtils, SDKErrors } from '@kiltprotocol/utils'
import * as Did from '@kiltprotocol/did'
import { isHex } from '@polkadot/util'

import {verifyMessageEnvelope} from './MessageEnvelope'
import type {
  IMessage,
  MessageBody,
} from '../types'

/**
     * Checks if the message body is well-formed.
     *
     * @param body The message body.
     */
export function verifyMessageBody(body: MessageBody): void {
  switch (body.type) {
  case 'submit-terms': {
    Claim.verifyDataStructure(body.content.claim)
    body.content.legitimations.forEach((credential) => Credential.verifyDataStructure(credential))
    if (body.content.delegationId) {
      DataUtils.verifyIsHex(body.content.delegationId)
    }
    if (body.content.quote) {
      Quote.validateQuoteSchema(Quote.QuoteSchema, body.content.quote)
    }
    if (body.content.cTypes) {
      body.content.cTypes.forEach((val) => CType.verifyDataStructure(val))
    }
    break
  }
  case 'request-attestation': {
    Credential.verifyDataStructure(body.content.credential)
    if (body.content.quote) {
      Quote.validateQuoteSchema(Quote.QuoteSchema, body.content.quote)
    }
    break
  }
  case 'submit-attestation': {
    Attestation.verifyDataStructure(body.content.attestation)
    break
  }
  case 'reject-attestation': {
    if (!isHex(body.content)) {
      throw new SDKErrors.HashMalformedError()
    }
    break
  }
  case 'request-credential': {
    body.content.cTypes.forEach(({ cTypeHash, trustedAttesters, requiredProperties }): void => {
      DataUtils.verifyIsHex(cTypeHash)
      trustedAttesters?.forEach((did) => Did.validateUri(did, 'Did'))
      requiredProperties?.forEach((requiredProps) => {
        if (typeof requiredProps !== 'string') throw new TypeError('Required properties is expected to be a string')
      })
    })
    break
  }
  case 'submit-credential': {
    body.content.forEach((presentation) => {
      Credential.verifyDataStructure(presentation)
      if (!Did.isDidSignature(presentation.claimerSignature)) {
        throw new SDKErrors.SignatureMalformedError()
      }
    })
    break
  }

  default:
    throw new SDKErrors.UnknownMessageBodyTypeError()
  }
}

/**
     * Verifies that the sender of a [[Message]] is also the owner of it, e.g the owner's and sender's DIDs refer to the same subject.
     *
     * @param message The [[Message]] object which needs to be decrypted.
     * @param message.body The body of the [[Message]] which depends on the [[BodyType]].
     * @param message.sender The sender's DID taken from the [[IMessage]].
     */
export function ensureOwnerIsSender({ body, sender }: IMessage): void {
  switch (body.type) {
  case 'request-attestation':
    {
      const requestAttestation = body
      if (!Did.isSameSubject(requestAttestation.content.credential.claim.owner, sender)) {
        throw new SDKErrors.IdentityMismatchError('Claim', 'Sender')
      }
    }
    break
  case 'submit-attestation':
    {
      const submitAttestation = body
      if (!Did.isSameSubject(submitAttestation.content.attestation.owner, sender)) {
        throw new SDKErrors.IdentityMismatchError('Attestation', 'Sender')
      }
    }
    break
  case 'submit-credential':
    {
      const submitClaimsForCtype = body
      submitClaimsForCtype.content.forEach((presentation) => {
        if (!Did.isSameSubject(presentation.claim.owner, sender)) {
          throw new SDKErrors.IdentityMismatchError('Claims', 'Sender')
        }
      })
    }
    break
  default:
  }
}

/**
     * Checks the message structure and body contents (e.g. Hashes match, ensures the owner is the sender).
     * Throws, if a check fails.
     *
     * @param decryptedMessage The decrypted message to check.
     */
export function verify(decryptedMessage: IMessage): void {
  verifyMessageBody(decryptedMessage.body)
  verifyMessageEnvelope(decryptedMessage)
  ensureOwnerIsSender(decryptedMessage)
}


