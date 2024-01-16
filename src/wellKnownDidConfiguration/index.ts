/**
 * Copyright (c) 2018-2024, Built on KILT.
 *
 * This source code is licensed under the BSD 4-Clause "Original" license
 * found in the LICENSE file in the root directory of this source tree.
 */

import { DidResolver } from '@kiltprotocol/sdk-js'
import { CType, W3C_CREDENTIAL_TYPE, W3C_CREDENTIAL_CONTEXT_URL, DataIntegrity } from '@kiltprotocol/credentials'
import { Signers } from '@kiltprotocol/utils'
import type { SignerInterface, Did, DidUrl, DidDocument } from '@kiltprotocol/types'
import type { DomainLinkageCredential, DidConfigResource } from '../types/index.js'
import { hexToU8a, u8aToHex } from '@polkadot/util'
import { KILT_SELF_SIGNED_PROOF_TYPE, KILT_VERIFIABLECREDENTIAL_TYPE, SelfSignedProof } from '../types/LegacyProofs.js'
import { blake2AsU8a } from '@polkadot/util-crypto'
import { validateDid, verifyDidSignature } from '@kiltprotocol/did'

export {
  W3C_CREDENTIAL_TYPE as DEFAULT_VERIFIABLECREDENTIAL_TYPE,
  KILT_VERIFIABLECREDENTIAL_TYPE,
  KILT_SELF_SIGNED_PROOF_TYPE,
  W3C_CREDENTIAL_CONTEXT_URL as DID_VC_CONTEXT,
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

export const DOMAIN_LINKAGE_CREDENTIAL_TYPE = 'DomainLinkageCredential'

export async function createCredential(
  signers: SignerInterface[],
  origin: string,
  did: Did | DidDocument,
  {
    proofType = KILT_SELF_SIGNED_PROOF_TYPE,
    expirationDate = new Date(Date.now() + 1000 * 60 * 60 * 24 * 365 * 5),
  }: {
    expirationDate?: Date
    proofType?: typeof KILT_SELF_SIGNED_PROOF_TYPE | typeof DataIntegrity.PROOF_TYPE
  } = {}
): Promise<DomainLinkageCredential> {
  checkOrigin(origin)

  const document = await (async () => {
    if (typeof did === 'string') {
      const { didDocument } = await DidResolver.resolve(did, {})
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
    '@context': [W3C_CREDENTIAL_CONTEXT_URL, DID_CONFIGURATION_CONTEXT],
    issuer: document.id,
    issuanceDate: new Date().toISOString(),
    expirationDate: expirationDate.toISOString(),
    type: [W3C_CREDENTIAL_TYPE, DOMAIN_LINKAGE_CREDENTIAL_TYPE],
    credentialSubject: {
      id: document.id,
      origin,
    },
  }

  const signer = Signers.selectSigner(
    signers,
    Signers.select.byDid(document, { verificationRelationship: 'assertionMethod' }),
    Signers.select.verifiableOnChain()
  )
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
    case DataIntegrity.PROOF_TYPE: {
      return DataIntegrity.signWithDid({
        document: credentialBody,
        signerDid: document,
        signers,
        proofPurpose: 'assertionMethod',
        expires: expirationDate,
      })
    }
    default:
      throw new Error(`unknown proof type ${proofType}`)
  }
}

function checkIsDomainLinkageCredential(credential: DomainLinkageCredential): void {
  if (
    !(
      credential['@context']?.[0] === W3C_CREDENTIAL_CONTEXT_URL &&
      credential['@context']?.[1] === DID_CONFIGURATION_CONTEXT
    )
  ) {
    throw new Error(`credential must include contexts ${[W3C_CREDENTIAL_CONTEXT_URL, DID_CONFIGURATION_CONTEXT]}`)
  }
  if (!(credential.type?.includes(DOMAIN_LINKAGE_CREDENTIAL_TYPE) && credential.type?.includes(W3C_CREDENTIAL_TYPE))) {
    throw new Error(`credential must have types ${W3C_CREDENTIAL_TYPE} & ${DOMAIN_LINKAGE_CREDENTIAL_TYPE}`)
  }
  try {
    validateDid(credential.credentialSubject?.id, 'Did')
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
  signers: SignerInterface[],
  origin: string,
  did: Did,
  {
    expirationDate = new Date(Date.now() + 1000 * 60 * 60 * 24 * 365 * 5),
  }: {
    expirationDate?: Date
  } = {}
): Promise<DidConfigResource> {
  checkOrigin(origin as string)

  const { didDocument } = await DidResolver.resolve(did, {})

  if (!didDocument) {
    throw new Error('No Did found: Please create a Full DID')
  }

  const credentials = await Promise.all([
    createCredential(signers, origin, didDocument, { proofType: DataIntegrity.PROOF_TYPE, expirationDate }),
    createCredential(signers, origin, didDocument, { proofType: KILT_SELF_SIGNED_PROOF_TYPE, expirationDate }),
  ])

  return didConfigResourceFromCredentials(credentials)
}

async function verifyDomainLinkageCredential(
  credential: DomainLinkageCredential,
  expectedOrigin: string,
  { expectedDid, allowUnsafe = false }: { expectedDid?: Did; allowUnsafe?: boolean } = {}
): Promise<Did> {
  checkIsDomainLinkageCredential(credential)

  const { credentialSubject, proof } = credential
  const Did = credentialSubject.id

  if (expectedOrigin !== credentialSubject.origin) throw new Error('origin does not match expected')
  if (expectedDid && expectedDid !== Did) throw new Error('DID does not match expected')

  const now = new Date().getTime()
  if (new Date(credential.issuanceDate).getTime() > now) {
    throw new Error('issuanceDate is in the future')
  }
  if (new Date(credential.expirationDate).getTime() < now) {
    throw new Error('expirationDate is in the past')
  }

  switch (proof.type) {
    case KILT_SELF_SIGNED_PROOF_TYPE: {
      // rootHash is a fallback for older domain linkage credential types
      const { rootHash } = credentialSubject as any
      let docHash: Uint8Array
      if (rootHash && allowUnsafe) {
        docHash = hexToU8a(rootHash)
      } else {
        const copy = JSON.parse(JSON.stringify(credential))
        delete copy.credentialSubject.rootHash
        delete copy.proof.signature
        docHash = blake2AsU8a(JSON.stringify(copy))
      }
      await verifyDidSignature({
        expectedVerificationRelationship: 'assertionMethod',
        signature: hexToU8a(proof.signature),
        signerUrl: proof.verificationMethod as DidUrl,
        message: docHash,
      })
      break
    }
    case DataIntegrity.PROOF_TYPE: {
      const cryptosuite = DataIntegrity.getCryptosuiteByNameOrAlgorithm(proof.cryptosuite)
      if (!cryptosuite) {
        throw new Error(`unknown cryptosuite ${proof.cryptosuite}`)
      }
      if (
        !(await DataIntegrity.verifyProof(credential, proof, {
          cryptosuites: [cryptosuite],
          expectedProofPurpose: 'assertionMethod',
          expectedController: expectedDid,
        }))
      ) {
        throw new Error('failed to verify proof')
      }
      break
    }
  }
  return Did
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
  { expectedDid, allowUnsafe = false }: { expectedDid?: Did; allowUnsafe?: boolean } = {}
): Promise<Did> {
  // Verification steps outlined in Well Known DID Configuration
  // https://identity.foundation/.well-known/resources/did-configuration/#did-configuration-resource-verification

  checkOrigin(expectedOrigin)

  return asyncSome(didConfig.linked_dids, (credential) =>
    verifyDomainLinkageCredential(credential, expectedOrigin, { expectedDid, allowUnsafe })
  ).catch(() => {
    throw new Error('Did Configuration Resource could not be verified')
  })
}
