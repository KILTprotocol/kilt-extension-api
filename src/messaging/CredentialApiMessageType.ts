/**
 * Copyright (c) 2018-2024, Built on KILT.
 *
 * This source code is licensed under the BSD 4-Clause "Original" license
 * found in the LICENSE file in the root directory of this source tree.
 */

import { Attestation, Claim, Credential } from '@kiltprotocol/legacy-credentials'
import { CType } from '@kiltprotocol/credentials'
import { DataUtils } from '@kiltprotocol/utils'
import * as Did from '@kiltprotocol/did'
import { isHex } from '@polkadot/util'

import {
  isSubmitTerms,
  isRequestAttestation,
  isSubmitAttestation,
  isRejectAttestation,
  isSubmitCredential,
  isIRequestCredential,
  isIRequestPayment,
  isIConfirmPayment,
} from '../utils/index.js'
import * as MessageError from './Error.js'
import type { IMessage, CredentialApiMessageBody } from '../types/index.js'
import { verifyMessageEnvelope } from './MessageEnvelope.js'
import { validateQuoteSchema } from '../quote/Quote.js'
import { QuoteSchema } from '../quote/QuoteSchema.js'

/**
 * Checks if the message body is well-formed.
 *
 * @param body The message body.
 */
export function assertKnownMessageBody(message: IMessage): void {
  if (isSubmitTerms(message)) {
    const { body } = message
    Claim.verifyDataStructure(body.content.claim)
    body.content.legitimations.forEach((credential) => Credential.verifyDataStructure(credential))
    if (body.content.delegationId) {
      DataUtils.verifyIsHex(body.content.delegationId)
    }
    if (body.content.quote) {
      validateQuoteSchema(QuoteSchema, body.content.quote)
    }
    if (body.content.cTypes) {
      body.content.cTypes.forEach((val) => CType.verifyDataStructure(val))
    }
  } else if (isRequestAttestation(message)) {
    Credential.verifyDataStructure(message.body.content.credential)
    if (message.body.content.quote) {
      validateQuoteSchema(QuoteSchema, message.body.content.quote)
    }
  } else if (isSubmitAttestation(message)) {
    Attestation.verifyDataStructure(message.body.content.attestation)
  } else if (isRejectAttestation(message)) {
    if (!isHex(message.body.content)) {
      throw new MessageError.HashMalformedError()
    }
  } else if (isIRequestCredential(message)) {
    message.body.content.cTypes.forEach(({ cTypeHash, trustedAttesters, requiredProperties }) => {
      DataUtils.verifyIsHex(cTypeHash)
      trustedAttesters?.forEach((did) => Did.validateDid(did, 'Did'))
      requiredProperties?.forEach((requiredProps) => {
        if (typeof requiredProps !== 'string') throw new TypeError('Required properties is expected to be a string')
      })
    })
  } else if (isSubmitCredential(message)) {
    message.body.content.forEach((presentation) => {
      Credential.verifyDataStructure(presentation)
      if (!Did.isDidSignature(presentation.claimerSignature)) {
        throw new MessageError.SignatureMalformedError()
      }
    })
  } else if (isIRequestPayment(message) || isIConfirmPayment(message)) {
    return
  } else {
    throw new MessageError.UnknownMessageBodyTypeError()
  }
}

/**
 * Verifies that the sender of a [[Message]] is also the owner of it, e.g the owner's and sender's DIDs refer to the same subject.
 *
 * @param message The [[Message]] object which needs to be decrypted.
 * @param message.body The body of the [[Message]] which depends on the [[BodyType]].
 * @param message.sender The sender's DID taken from the [[IMessage]].
 */

export function ensureOwnerIsSender(message: IMessage): void {
  if (isRequestAttestation(message)) {
    if (!Did.isSameSubject(message.body.content.credential.claim.owner, message.sender)) {
      throw new MessageError.IdentityMismatchError('Sender not matching claim owner')
    }
  } else if (isSubmitAttestation(message)) {
    if (!Did.isSameSubject(message.body.content.attestation.owner, message.sender)) {
      throw new MessageError.IdentityMismatchError('Sender not matching attestation issuer')
    }
  } else if (isSubmitCredential(message)) {
    message.body.content.forEach((presentation) => {
      if (!Did.isSameSubject(presentation.claim.owner, message.sender)) {
        throw new MessageError.IdentityMismatchError('Sender not matching claim owner')
      }
    })
  }
}

/**
 * Checks the message structure and body contents (e.g. Hashes match, ensures the owner is the sender).
 * Throws, if a check fails.
 *
 * @param decryptedMessage The decrypted message to check.
 */
export function assertKnownMessage(decryptedMessage: IMessage): CredentialApiMessageBody {
  assertKnownMessageBody(decryptedMessage)
  verifyMessageEnvelope(decryptedMessage)
  ensureOwnerIsSender(decryptedMessage)
  return decryptedMessage.body as CredentialApiMessageBody
}
