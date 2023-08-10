/* eslint-disable @typescript-eslint/no-explicit-any */
import { IAttestation, ICredentialPresentation, IRequestCredentialContent } from '@kiltprotocol/types'

import type {
  IMessage,
  IMessageBodyBase,
  IRejectAttestation,
  IRequestAttestation,
  IRequestCredential,
  ISubmitAttestation,
  ISubmitCredential,
  ISubmitTerms,
} from '../types'

export function isIMessage<Body extends IMessageBodyBase>(message: any): message is IMessage<Body> {
  if (
    typeof message !== 'object' ||
    !('body' in message) ||
    !('type' in message.body) ||
    !('createdAt' in message) ||
    !('sender' in message) ||
    !('receiver' in message) ||
    typeof message.createdAt !== 'number' ||
    typeof message.sender !== 'string' ||
    typeof message.receiver !== 'string'
  ) {
    return false
  }

  const { messageId, receivedAt, inReplyTo, references } = message

  return (
    (typeof messageId === 'undefined' || typeof messageId === 'string') &&
    (typeof receivedAt === 'undefined' || typeof receivedAt === 'number') &&
    (typeof inReplyTo === 'undefined' || typeof inReplyTo === 'string') &&
    (Array.isArray(references) || typeof references === 'undefined')
  )
}

export function isSubmitTerms(message: IMessage): message is IMessage<ISubmitTerms> {
  if (
    !isIMessage(message) ||
    message.body.type !== 'submit-terms' ||
    typeof message.body.content !== 'object' ||
    message.body.content === null
  ) {
    return false
  }

  const { claim, legitimations, delegationId, quote, cTypes } = message.body.content as ISubmitTerms['content']

  return (
    claim !== undefined &&
    legitimations !== undefined &&
    (legitimations === undefined || Array.isArray(legitimations)) &&
    (delegationId === undefined || typeof delegationId === 'string') &&
    (quote === undefined || typeof quote === 'object') &&
    (cTypes === undefined || Array.isArray(cTypes))
  )
}

export function isSubmitAttestation(message: IMessage): message is IMessage<ISubmitAttestation> {
  if (!isIMessage(message) || message.body.type !== 'submit-attestation') {
    return false
  }

  const content = message.body.content as ISubmitAttestation['content']

  return (
    typeof content === 'object' && content !== null && 'attestation' in content && isIAttestation(content.attestation)
  )
}

export function isIAttestation(body: any): body is IAttestation {
  if (typeof body !== 'object') {
    return false
  }

  const { claimHash, cTypeHash, owner, delegationId, revoked } = body

  return (
    typeof claimHash === 'string' &&
    typeof cTypeHash === 'string' &&
    typeof owner === 'string' &&
    (delegationId === null || typeof delegationId === 'string') &&
    typeof revoked === 'boolean'
  )
}

export function isRejectAttestation(message: IMessage): message is IMessage<IRejectAttestation> {
  return (
    isIMessage(message) &&
    message.body.type === 'reject-attestation' &&
    typeof message.body === 'object' &&
    'content' in message.body &&
    typeof message.body.content === 'string'
  )
}

export function isRequestAttestation(message: IMessage): message is IMessage<IRequestAttestation> {
  if (!isIMessage(message) || !('content' in message.body)) {
    return false
  }

  const content = message.body.content as IRequestAttestation['content']

  return (
    message.body.type === 'request-attestation' &&
    'credential' in content &&
    typeof content.credential === 'object' &&
    (typeof content.quote === 'undefined' || typeof content.quote === 'object')
  )
}

export function isIRequestCredential(message: IMessage): message is IMessage<IRequestCredential> {
  return (
    isIMessage(message) &&
    message.body.type === 'request-credential' &&
    isIRequestCredentialContent(message.body.content)
  )
}

export function isIRequestCredentialContent(body: any): body is IRequestCredentialContent {
  if (
    typeof body !== 'object' ||
    body === null ||
    !Array.isArray(body.cTypes) ||
    !body.cTypes.every(
      (cType: any) =>
        typeof cType === 'object' &&
        cType !== null &&
        'cTypeHash' in cType &&
        typeof cType.cTypeHash === 'string' &&
        (typeof cType.trustedAttesters === 'undefined' || Array.isArray(cType.trustedAttesters)) &&
        (typeof cType.requiredProperties === 'undefined' || Array.isArray(cType.requiredProperties))
    )
  ) {
    return false
  }

  if ('challenge' in body && typeof body.challenge !== 'undefined' && typeof body.challenge !== 'string') {
    return false
  }

  return true
}

export function isSubmitCredential(message: IMessage): message is IMessage<ISubmitCredential> {
  return (
    isIMessage(message) &&
    message.body.type === 'submit-credential' &&
    Array.isArray(message.body.content) &&
    message.body.content.every(isICredentialPresentation)
  )
}

function isICredentialPresentation(body: any): body is ICredentialPresentation {
  return (
    typeof body === 'object' &&
    body !== null &&
    'claimerSignature' in body &&
    typeof body.claimerSignature === 'object' &&
    'claim' in body &&
    'claimNonceMap' in body &&
    'claimHashes' in body &&
    'delegationId' in body &&
    (body.delegationId === null || typeof body.delegationId === 'string') &&
    'legitimations' in body &&
    Array.isArray(body.legitimations) &&
    'rootHash' in body &&
    typeof body.rootHash === 'string' &&
    ('challenge' in body.claimerSignature ? typeof body.claimerSignature.challenge === 'string' : true)
  )
}
