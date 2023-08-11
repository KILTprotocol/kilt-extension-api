/**
 * Copyright (c) 2018-2023, BOTLabs GmbH.
 *
 * This source code is licensed under the BSD 4-Clause "Original" license
 * found in the LICENSE file in the root directory of this source tree.
 */

import {
  Did,
  CType,
  Credential,
  Claim,
  SignCallback,
  DidUri,
  Utils,
  ICredentialPresentation,
  DidResourceUri,
} from '@kiltprotocol/sdk-js'
import { DomainLinkageCredential, DomainLinkageProof, DidConfigResource } from '../types'
import {
  SelfSignedProof,
  constants,
  fromCredentialAndAttestation,
  Proof,
  CredentialDigestProof,
  verification,
  VerifiableCredential,
} from '@kiltprotocol/vc-export'
import { hexToU8a, isHex } from '@polkadot/util'

const {
  DEFAULT_VERIFIABLECREDENTIAL_TYPE,
  KILT_VERIFIABLECREDENTIAL_TYPE,
  KILT_SELF_SIGNED_PROOF_TYPE,
  DEFAULT_VERIFIABLECREDENTIAL_CONTEXT,
  KILT_CREDENTIAL_DIGEST_PROOF_TYPE,
} = constants

export {
  DEFAULT_VERIFIABLECREDENTIAL_TYPE,
  KILT_VERIFIABLECREDENTIAL_TYPE,
  KILT_SELF_SIGNED_PROOF_TYPE,
  DEFAULT_VERIFIABLECREDENTIAL_CONTEXT as DID_VC_CONTEXT,
}
export const DID_CONFIGURATION_CONTEXT = 'https://identity.foundation/.well-known/did-configuration/v1'

export const ctypeDomainLinkage = CType.fromProperties('Domain Linkage Credential', {
  origin: {
    type: 'string',
    format: 'uri',
  },
})

function checkOrigin(input: string) {
  const { origin, protocol } = new URL(input)
  if (input !== origin) {
    throw new Error(`Not a valid origin: ${input}`)
  }
  if (!/^https?:$/.test(protocol)) {
    throw new Error('http/https origin expected')
  }
}

export async function createCredential(
  signCallback: SignCallback,
  origin: string,
  didUri: DidUri
): Promise<ICredentialPresentation> {
  checkOrigin(origin)

  const fullDid = await Did.resolve(didUri)

  if (!fullDid?.document) {
    throw new Error('No Did found: Please create a Full DID')
  }

  const { document } = fullDid

  const assertionKey = document.assertionMethod?.[0]

  if (!assertionKey) {
    throw new Error('Full DID doesnt have assertion key: Please add assertion key')
  }

  const domainClaimContents = {
    origin,
  }

  const claim = Claim.fromCTypeAndClaimContents(ctypeDomainLinkage, domainClaimContents, document.uri)

  const credential = Credential.fromClaim(claim)

  const presentation = await Credential.createPresentation({
    credential,
    signCallback,
  })

  if (presentation.claimerSignature.keyUri !== `${document.uri}${assertionKey.id}`) {
    throw new Error('The credential presentation needs to be signed with the assertionMethod key')
  }

  return presentation
}

export const DOMAIN_LINKAGE_CREDENTIAL_TYPE = 'DomainLinkageCredential'

export async function didConfigResourceFromCredential(
  credential: ICredentialPresentation,
  expirationDate: string = new Date(Date.now() + 1000 * 60 * 60 * 24 * 365 * 5).toISOString()
): Promise<DidConfigResource> {
  if (!Credential.isPresentation(credential)) {
    throw new Error('Input must be an IPresentation')
  }
  const claimContents = credential.claim.contents
  CType.verifyClaimAgainstSchema(claimContents, ctypeDomainLinkage)

  const { origin } = claimContents
  checkOrigin(origin as string)

  if (!(credential.claim.owner && origin)) {
    throw new Error('Claim must have an owner and an origin property')
  }
  const propsToRemove = Object.keys(claimContents).filter((i) => i !== 'origin')
  const originOnlyCredential = Credential.removeClaimProperties(credential, propsToRemove)

  const {
    proof: allProofs,
    credentialSubject,
    id: _,
    legitimationIds: __,
    ...VC
  } = fromCredentialAndAttestation(originOnlyCredential, {
    owner: credential.claim.owner,
  } as any)

  const ssProof = (allProofs as Proof[]).find(({ type }) => type === KILT_SELF_SIGNED_PROOF_TYPE) as SelfSignedProof
  const digProof = (allProofs as Proof[]).find(
    ({ type }) => type === KILT_CREDENTIAL_DIGEST_PROOF_TYPE
  ) as CredentialDigestProof

  const proof: DomainLinkageProof = {
    ...ssProof,
    ...digProof,
    rootHash: credential.rootHash,
    type: [KILT_SELF_SIGNED_PROOF_TYPE, KILT_CREDENTIAL_DIGEST_PROOF_TYPE],
  }
  return {
    '@context': DID_CONFIGURATION_CONTEXT,
    linked_dids: [
      {
        ...VC,
        '@context': [DEFAULT_VERIFIABLECREDENTIAL_CONTEXT, DID_CONFIGURATION_CONTEXT],
        expirationDate,
        type: [DEFAULT_VERIFIABLECREDENTIAL_TYPE, DOMAIN_LINKAGE_CREDENTIAL_TYPE],
        proof,
        credentialSubject: {
          id: credentialSubject['@id'] as DidUri, // canonicalize @id to id
          origin: credentialSubject.origin as string,
          // @ts-expect-error for compatibility with older implementations, add the credential rootHash (which is also contained in the credential id)
          rootHash: credential.rootHash,
        },
      },
    ],
  }
}

async function verifyDomainLinkageCredential(
  credential: DomainLinkageCredential,
  expectedOrigin: string,
  expectedDid?: DidUri
): Promise<DidUri> {
  const { issuer, credentialSubject, proof } = credential

  if (issuer !== credentialSubject.id) throw new Error('issuer and credential subject must be identical')

  const didUri = credentialSubject.id
  Did.validateUri(didUri, 'Did')

  if (expectedOrigin !== credentialSubject.origin) throw new Error('origin does not match expected')
  if (expectedDid && expectedDid !== didUri) throw new Error('DID does not match expected')

  // get root hash incl fallback for older domain linkage credential types
  const { rootHash = proof.rootHash, ...cleanSubject } = credentialSubject as any
  if (!isHex(rootHash)) {
    throw new Error('rootHash must be a hex encoded string')
  }

  const pType = Array.isArray(proof.type) ? proof.type : [proof.type]
  if (!pType.includes(KILT_SELF_SIGNED_PROOF_TYPE)) {
    throw new Error(`proof type must include ${KILT_SELF_SIGNED_PROOF_TYPE}`)
  }

  await Did.verifyDidSignature({
    expectedVerificationMethod: 'assertionMethod',
    signature: hexToU8a(proof.signature),
    keyUri: proof.verificationMethod as DidResourceUri,
    message: Utils.Crypto.coToUInt8(rootHash),
  })

  if (pType.includes(KILT_CREDENTIAL_DIGEST_PROOF_TYPE)) {
    await verification.verifyCredentialDigestProof(
      {
        ...credential,
        credentialSubject: cleanSubject,
        id: `kilt:cred:${rootHash}`,
      } as unknown as VerifiableCredential,
      { ...proof, type: KILT_CREDENTIAL_DIGEST_PROOF_TYPE }
    )
  }

  return didUri
}

async function asyncSome<T>(
  credentials: DomainLinkageCredential[],
  verify: (credential: DomainLinkageCredential) => Promise<T>
): Promise<T> {
  return new Promise((resolve, reject) => {
    const promises = credentials.map((credential) => verify(credential).then(resolve))
    Promise.allSettled(promises).then(reject)
  })
}

/**
 * Verifies a DID Configuration Resource created by this library.
 * Verification is successful if any of the Domain Linkage Credentials in linked_dids can be verified.
 *
 * @param didConfig A Did Configuration Resource as created by [[makeDidConfigResourceFromCredential]].
 * @param expectedOrigin The origin (domain) from which the resource was loaded.
 * @param expectedDid If specified, this will only accept DL credentials issued by and for this DID.
 * @returns The credential subject (DID) contained within the first credential to be successfully verified.
 */
export async function verifyDidConfigResource(
  didConfig: DidConfigResource,
  expectedOrigin: string,
  expectedDid?: DidUri
): Promise<DidUri> {
  // Verification steps outlined in Well Known DID Configuration
  // https://identity.foundation/.well-known/resources/did-configuration/#did-configuration-resource-verification

  checkOrigin(expectedOrigin)

  return asyncSome(didConfig.linked_dids, (credential) =>
    verifyDomainLinkageCredential(credential, expectedOrigin, expectedDid)
  ).catch(() => {
    throw new Error('Did Configuration Resource could not be verified')
  })
}
