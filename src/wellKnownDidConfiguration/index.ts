/**
 * Copyright (c) 2018-2024, Built on KILT.
 *
 * This source code is licensed under the BSD 4-Clause "Original" license
 * found in the LICENSE file in the root directory of this source tree.
 */

import { Did, CType, DidUri, DidResourceUri, ConformingDidDocument } from '@kiltprotocol/sdk-js'
import type { DomainLinkageCredential, DidConfigResource, DataIntegrityProof } from '../types/index.js'
import { SelfSignedProof, constants } from '@kiltprotocol/vc-export'
import { hexToU8a, u8aToHex } from '@polkadot/util'
import type { SignerInterface } from '@kiltprotocol/jcs-data-integrity-proofs-common'
import * as ed25519 from '@kiltprotocol/eddsa-jcs-2022'
import * as sr25519 from '@kiltprotocol/sr25519-jcs-2023'
import * as es256k from '@kiltprotocol/es256k-jcs-2023'

import { base58Decode, base58Encode, blake2AsU8a } from '@polkadot/util-crypto'

const {
  DEFAULT_VERIFIABLECREDENTIAL_TYPE,
  KILT_VERIFIABLECREDENTIAL_TYPE,
  KILT_SELF_SIGNED_PROOF_TYPE,
  DEFAULT_VERIFIABLECREDENTIAL_CONTEXT,
} = constants

export {
  DEFAULT_VERIFIABLECREDENTIAL_TYPE,
  KILT_VERIFIABLECREDENTIAL_TYPE,
  KILT_SELF_SIGNED_PROOF_TYPE,
  DEFAULT_VERIFIABLECREDENTIAL_CONTEXT as DID_VC_CONTEXT,
}
export const DID_CONFIGURATION_CONTEXT = 'https://identity.foundation/.well-known/did-configuration/v1'
export const DATA_INTEGRITY_CONTEXT = 'https://w3id.org/security/data-integrity/v1'

export const ctypeDomainLinkage = CType.fromProperties('Domain Linkage Credential', {
  origin: {
    type: 'string',
    format: 'uri',
  },
})

const MULTIBASE_BASE58BTC_HEADER = 'z'

function checkOrigin(input: string) {
  const { origin, protocol } = new URL(input)
  if (input !== origin) {
    throw new Error(`Not a valid origin: ${input}`)
  }
  if (!/^https?:$/.test(protocol)) {
    throw new Error('http/https origin expected')
  }
}

export const DOMAIN_LINKAGE_CREDENTIAL_TYPE = 'DomainLinkageCredential' as const
export const DATA_INTEGRITY_PROOF_TYPE = 'DataIntegrity' as const

const suites = [ed25519.cryptosuite, sr25519.cryptosuite, es256k.cryptosuite]

export async function createCredential(
  signer: SignerInterface,
  origin: string,
  did: DidUri | ConformingDidDocument,
  {
    proofType = KILT_SELF_SIGNED_PROOF_TYPE,
    expirationDate = new Date(Date.now() + 1000 * 60 * 60 * 24 * 365 * 5),
  }: {
    expirationDate?: Date
    proofType?: typeof KILT_SELF_SIGNED_PROOF_TYPE | typeof DATA_INTEGRITY_PROOF_TYPE
  } = {}
): Promise<DomainLinkageCredential> {
  checkOrigin(origin)

  const document = await (async () => {
    if (typeof did === 'string') {
      const { didDocument } = await Did.resolveCompliant(did)
      if (!didDocument) {
        throw new Error('Failed to resolve DID ' + did)
      }
      return didDocument
    } else if (typeof did === 'object' && did?.id) {
      return did
    } else {
      throw new Error('must pass a DID or DID Document for the did parameter')
    }
  })()

  if (!document.assertionMethod?.length) {
    throw new Error('DID Document does not contain assertion key: Please add assertion key')
  }

  const credentialBody: Omit<DomainLinkageCredential, 'proof'> = {
    '@context': [DEFAULT_VERIFIABLECREDENTIAL_CONTEXT, DID_CONFIGURATION_CONTEXT],
    issuer: document.id,
    issuanceDate: new Date().toISOString(),
    expirationDate: expirationDate.toISOString(),
    type: [DEFAULT_VERIFIABLECREDENTIAL_TYPE, DOMAIN_LINKAGE_CREDENTIAL_TYPE],
    credentialSubject: {
      id: document.id,
      origin,
    },
  }

  if (!signer) {
    throw new Error('No signer available for an assertion method of the DID')
  }

  switch (proofType) {
    case KILT_SELF_SIGNED_PROOF_TYPE: {
      const credential = {
        ...credentialBody,
        proof: {
          type: KILT_SELF_SIGNED_PROOF_TYPE,
          verificationMethod: signer.id,
          proofPurpose: 'assertionMethod',
        },
      } as DomainLinkageCredential
      const docHash = blake2AsU8a(JSON.stringify(credential))
      const signature = await signer.sign({ data: docHash })
      ;(credential.proof as SelfSignedProof).signature = u8aToHex(signature)
      // @ts-expect-error for backwards compatibility
      credential.credentialSubject.rootHash = u8aToHex(docHash)
      return credential
    }
    case DATA_INTEGRITY_PROOF_TYPE: {
      credentialBody['@context'].push(DATA_INTEGRITY_CONTEXT)
      const suite = suites.find(({ requiredAlgorithm }) => requiredAlgorithm === signer.algorithm)
      if (!suite) {
        throw new Error(`unknown signer algorithm ${signer.algorithm}`)
      }
      const proof = {
        type: DATA_INTEGRITY_PROOF_TYPE,
        verificationMethod: signer.id,
        cryptosuite: suite.name,
        proofPurpose: 'assertionMethod',
        created: credentialBody.issuanceDate,
        expires: credentialBody.expirationDate,
        domain: origin,
      } as DataIntegrityProof
      const verifyData = await suite.createVerifyData({ document: credentialBody, proof })
      const signature = await signer.sign({ data: verifyData })
      proof.proofValue = MULTIBASE_BASE58BTC_HEADER + base58Encode(signature)
      return { ...credentialBody, proof }
    }
    default:
      throw new Error(`unknown proof type ${proofType}`)
  }
}

function checkIsDomainLinkageCredential(credential: DomainLinkageCredential): void {
  if (
    !(
      credential['@context']?.[0] === DEFAULT_VERIFIABLECREDENTIAL_CONTEXT &&
      credential['@context']?.[1] === DID_CONFIGURATION_CONTEXT
    )
  ) {
    throw new Error(
      `credential must include contexts ${[DEFAULT_VERIFIABLECREDENTIAL_CONTEXT, DID_CONFIGURATION_CONTEXT]}`
    )
  }
  if (
    !(
      credential.type?.includes(DOMAIN_LINKAGE_CREDENTIAL_TYPE) &&
      credential.type?.includes(DEFAULT_VERIFIABLECREDENTIAL_TYPE)
    )
  ) {
    throw new Error(
      `credential must have types ${DEFAULT_VERIFIABLECREDENTIAL_TYPE} & ${DOMAIN_LINKAGE_CREDENTIAL_TYPE}`
    )
  }
  try {
    Did.validateUri(credential.credentialSubject?.id, 'Did')
  } catch {
    throw new Error('credentialSubject.id must be present and must be a DID')
  }
  if (credential.issuer !== credential.credentialSubject.id) {
    throw new Error('issuer and credentialSubject.id must be identical')
  }
  try {
    checkOrigin(credential.credentialSubject?.origin)
  } catch {
    throw new Error('credentialSubject.origin must be present and must be a valid domain origin')
  }
  if (typeof credential.issuanceDate !== 'string' || typeof credential.expirationDate !== 'string') {
    throw new Error('issuanceDate & expirationDate must be present and must be iso date-time strings')
  }
}

export function didConfigResourceFromCredentials(credentials: DomainLinkageCredential[]): DidConfigResource {
  credentials.forEach(checkIsDomainLinkageCredential)
  credentials.reduce((last, next) => {
    if (last.credentialSubject.origin !== next.credentialSubject.origin) {
      throw new Error('credentials should have the same origin property')
    }
    return last
  })
  return {
    '@context': DID_CONFIGURATION_CONTEXT,
    linked_dids: credentials,
  }
}

export async function createDidConfigResource(
  signer: SignerInterface,
  origin: string,
  did: DidUri,
  {
    expirationDate = new Date(Date.now() + 1000 * 60 * 60 * 24 * 365 * 5),
  }: {
    expirationDate?: Date
  } = {}
): Promise<DidConfigResource> {
  checkOrigin(origin as string)

  const { didDocument } = await Did.resolveCompliant(did)

  if (!didDocument) {
    throw new Error('No Did found: Please create a Full DID')
  }

  const credentials = await Promise.all([
    createCredential(signer, origin, didDocument as ConformingDidDocument, {
      proofType: DATA_INTEGRITY_PROOF_TYPE,
      expirationDate,
    }),
    createCredential(signer, origin, didDocument as ConformingDidDocument, {
      proofType: KILT_SELF_SIGNED_PROOF_TYPE,
      expirationDate,
    }),
  ])

  return didConfigResourceFromCredentials(credentials)
}

export async function verifyDomainLinkageCredential(
  credential: DomainLinkageCredential,
  expectedOrigin: string,
  { expectedDid, allowUnsafe = false }: { expectedDid?: DidUri; allowUnsafe?: boolean } = {}
): Promise<DidUri> {
  checkIsDomainLinkageCredential(credential)

  const { credentialSubject, proof } = credential
  const did = credentialSubject.id

  if (expectedOrigin !== credentialSubject.origin) throw new Error('origin does not match expected')
  if (expectedDid && expectedDid !== did) throw new Error('DID does not match expected')

  const now = new Date().getTime()
  if (new Date(credential.issuanceDate).getTime() > now) {
    throw new Error('issuanceDate is in the future')
  }
  if (new Date(credential.expirationDate).getTime() < now) {
    throw new Error('expirationDate is in the past')
  }

  switch (proof.type) {
    case KILT_SELF_SIGNED_PROOF_TYPE: {
      // @ts-expect-error rootHash is a fallback for older domain linkage credential types
      const { rootHash } = credentialSubject
      let docHash: Uint8Array
      if (rootHash && allowUnsafe) {
        docHash = hexToU8a(rootHash)
      } else {
        const copy = JSON.parse(JSON.stringify(credential))
        delete copy.credentialSubject.rootHash
        delete copy.proof.signature
        docHash = blake2AsU8a(JSON.stringify(copy))
      }
      await Did.verifyDidSignature({
        expectedVerificationMethod: 'assertionMethod',
        signature: hexToU8a(proof.signature),
        keyUri: proof.verificationMethod as DidResourceUri,
        message: docHash,
      })
      break
    }
    case DATA_INTEGRITY_PROOF_TYPE: {
      const cryptosuite = suites.find(({ name }) => name === proof.cryptosuite)
      if (!cryptosuite) {
        throw new Error(`unknown cryptosuite ${proof.cryptosuite}`)
      }
      if (!proof.proofValue.startsWith(MULTIBASE_BASE58BTC_HEADER)) {
        throw new Error('proofValue is required to be in multibase base58btc encoding')
      }
      if (proof.proofPurpose !== 'assertionMethod') {
        throw new Error('proof must have assertionMethod purpose')
      }
      if (proof.domain && proof.domain !== expectedOrigin) {
        throw new Error('proof must have assertionMethod purpose')
      }
      const signature = base58Decode(proof.proofValue.slice(1))
      const credentialCopy: Record<string, unknown> = { ...credential }
      delete credentialCopy.proof
      const verifyData = await cryptosuite.createVerifyData({ document: credentialCopy, proof })

      const { didDocument } = await Did.resolveCompliant(Did.parse(proof.verificationMethod as DidUri).did)

      const verificationMethod = didDocument?.verificationMethod?.find(({ id }) => proof.verificationMethod === id)
      if (
        !verificationMethod ||
        !didDocument?.assertionMethod?.some((fragment) => proof.verificationMethod.endsWith(fragment))
      ) {
        throw new Error(
          `Verification method ${proof.verificationMethod} could not be resolved to a valid assertionMethod`
        )
      }
      if (verificationMethod.controller !== did) {
        throw new Error(`expected controller ${did}, got ${verificationMethod.controller}`)
      }
      const verifier = await cryptosuite.createVerifier({ verificationMethod } as any)
      if ((await verifier.verify({ signature, data: verifyData })) !== true) {
        throw new Error('Failed to veriy DataIntegrity proof against signature')
      }
      break
    }
  }
  return did
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
  { expectedDid, allowUnsafe = false }: { expectedDid?: DidUri; allowUnsafe?: boolean } = {}
): Promise<DidUri> {
  // Verification steps outlined in Well Known DID Configuration
  // https://identity.foundation/.well-known/resources/did-configuration/#did-configuration-resource-verification

  checkOrigin(expectedOrigin)

  return asyncSome(didConfig.linked_dids, (credential) =>
    verifyDomainLinkageCredential(credential, expectedOrigin, { expectedDid, allowUnsafe })
  ).catch(() => {
    throw new Error('Did Configuration Resource could not be verified')
  })
}
