/* eslint-disable @typescript-eslint/no-explicit-any */
import { ICredentialPresentation } from '@kiltprotocol/types'

import type {
  IRejectAttestation,
  IRequestAttestation,
  IRequestCredential,
  IRequestCredentialContent,
  ISubmitAttestation,
  ISubmitCredential,
  ISubmitTerms,
  MessageBody,
} from '../types'

export function isSubmitTerms(body: MessageBody): body is ISubmitTerms {
  return (
    body.type === 'submit-terms' &&
    typeof body === 'object' &&
    'content' in body &&
    'claim' in body.content &&
    'legitimations' in body.content &&
    (typeof body.content.legitimations === 'undefined' || Array.isArray(body.content.legitimations)) &&
    (typeof body.content.delegationId === 'undefined' || typeof body.content.delegationId === 'string') &&
    (typeof body.content.quote === 'undefined' || typeof body.content.quote === 'object') &&
    (typeof body.content.cTypes === 'undefined' || Array.isArray(body.content.cTypes))
  )
}

export function isRequestAttestation(body: MessageBody): body is IRequestAttestation {
  return (
    body.type === 'request-attestation' &&
    typeof body === 'object' &&
    'credential' in body.content &&
    typeof body.content.credential === 'object' &&
    (typeof body.content.quote === 'undefined' || typeof body.content.quote === 'object')
  )
}

export  function isSubmitAttestation(body: MessageBody): body is ISubmitAttestation {
  return (
    body.type === 'submit-attestation' &&
    typeof body === 'object' &&
    'content' in body &&
    typeof body.content === 'object' &&
    'attestation' in body.content &&
    typeof body.content.attestation === 'object'
  )
}

export function isRejectAttestation(body: MessageBody): body is IRejectAttestation {
  return (
    body.type === 'reject-attestation' &&
    typeof body === 'object' &&
    'content' in body &&
    typeof body.content === 'string'
  )
}



export function isIRequestCredential(body: MessageBody): body is IRequestCredential {
  return (
    typeof body === 'object' &&
      body !== null &&
      'type' in body &&
      body.type === 'request-credential' &&
      'content' in body &&
      isIRequestCredentialContent(body.content)
  )
}

export function isIRequestCredentialContent(body: any): body is IRequestCredentialContent {
  if (
    typeof body !== 'object' ||
      body === null ||
      !Array.isArray(body.cTypes) ||
      !body.cTypes.every((cType : any) =>
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

  if ('challenge' in body &&  typeof body.challenge !== 'undefined' && typeof body.challenge !== 'string') {
    return false
  }

  return true
}

export function isSubmitCredential(body: MessageBody): body is ISubmitCredential {
  return (
    typeof body === 'object' &&
      body !== null &&
      'type' in body &&
      body.type === 'submit-credential' &&
      'content' in body &&
      Array.isArray(body.content) &&
      body.content.every(isICredentialPresentation)
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




