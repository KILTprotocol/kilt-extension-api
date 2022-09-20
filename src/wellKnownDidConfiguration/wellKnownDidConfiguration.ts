import {
  Did,
  CType,
  Credential,
  Claim,
  ICredential,
  SignCallback,
  DidUri,
  Utils,
  ICredentialPresentation,
} from '@kiltprotocol/sdk-js'
import {
  CredentialSubject,
  DomainLinkageCredential,
  VerifiableDomainLinkagePresentation,
} from '../types/types'
import * as validUrl from 'valid-url'

export const DEFAULT_VERIFIABLECREDENTIAL_TYPE = 'VerifiableCredential'
export const KILT_VERIFIABLECREDENTIAL_TYPE = 'KiltCredential2020'
export const KILT_SELF_SIGNED_PROOF_TYPE = 'KILTSelfSigned2020'

export const ctypeDomainLinkage = CType.fromSchema({
  $schema: 'http://kilt-protocol.org/draft-01/ctype#',
  title: 'Domain Linkage Credential',
  properties: {
    id: {
      type: 'string',
    },
    origin: {
      type: 'string',
    },
  },
  type: 'object',
})

export async function createCredential(
  assertionSigner: SignCallback,
  origin: string,
  didUri: DidUri
): Promise<ICredential> {
  const fullDid = await Did.resolve(didUri)

  if (!fullDid?.document) {
    throw new Error('No Did found: Please create a Full DID')
  }

  const { document } = fullDid

  await CType.verifyStored(ctypeDomainLinkage)

  const domainClaimContents = {
    id: document.uri,
    origin,
  }

  const claim = Claim.fromCTypeAndClaimContents(
    ctypeDomainLinkage,
    domainClaimContents,
    document.uri
  )

  const credential = Credential.fromClaim(claim)

  const assertionKey = document.assertionMethod?.[0]

  if (!assertionKey) {
    throw new Error(
      'Full DID doesnt have assertion key: Please add assertion key'
    )
  }

  return Credential.createPresentation({
    credential,
    signCallback: assertionSigner,
    claimerDid: document,
  })
}

export function getDomainLinkagePresentation(
  credential: ICredentialPresentation,
  expirationDate?: string
): VerifiableDomainLinkagePresentation {
  const claimContents = credential.claim.contents
  if (!claimContents.id && !claimContents.origin) {
    throw new Error('Claim contents do not content an id or origin')
  }

  let didUri: DidUri
  if (typeof claimContents.id !== 'string') {
    throw new Error('claim contents id is not a string')
  } else if (!Did.Utils.isUri(claimContents.id)) {
    throw new Error('Credential ID is not a did uri')
  } else {
    didUri = claimContents.id as DidUri
  }

  let origin: string
  if (typeof claimContents.origin !== 'string') {
    throw new Error('claim contents id is not a string')
  } else if (!validUrl.isUri(claimContents.origin)) {
    throw new Error('The claim contents origin is not a valid url')
  } else {
    origin = claimContents.origin
  }

  const credentialSubject: CredentialSubject = {
    id: didUri,
    origin,
    rootHash: credential.rootHash,
  }

  const issuer = didUri

  const issuanceDate = new Date().toISOString()

  if (!expirationDate) {
    expirationDate = new Date(
      Date.now() + 1000 * 60 * 60 * 24 * 365 * 5
    ).toISOString() // 5 years
  }

  const { claimerSignature } = credential

  if (!claimerSignature) {
    throw new Error('No Claimer Signature found in the credential')
  }

  // add self-signed proof
  const proof = {
    type: KILT_SELF_SIGNED_PROOF_TYPE,
    proofPurpose: 'assertionMethod',
    verificationMethod: claimerSignature.keyUri,
    signature: claimerSignature.signature,
    challenge: claimerSignature.challenge,
  }

  return {
    '@context': 'https://identity.foundation/.well-known/did-configuration/v1',
    linked_dids: [
      {
        '@context': [
          'https://www.w3.org/2018/credentials/v1',
          'https://identity.foundation/.well-known/did-configuration/v1',
        ],
        issuer,
        issuanceDate,
        expirationDate,
        type: [
          DEFAULT_VERIFIABLECREDENTIAL_TYPE,
          'DomainLinkageCredential',
          KILT_VERIFIABLECREDENTIAL_TYPE,
        ],
        credentialSubject,
        proof,
      },
    ],
  }
}

async function asyncSome(
  credentials: DomainLinkageCredential[],
  verify: (credential: DomainLinkageCredential) => Promise<boolean>
) {
  for (const credential of credentials) {
    if (await verify(credential)) return true
  }
  return false
}

export async function verifyDidConfigPresentation(
  didUri: DidUri,
  domainLinkageCredential: VerifiableDomainLinkagePresentation
): Promise<void> {
  // Verification steps outlined in Well Known DID Configuration
  // https://identity.foundation/.well-known/resources/did-configuration/#did-configuration-resource-verification

  const verified = await asyncSome(
    domainLinkageCredential.linked_dids,
    async (credential) => {
      const { issuer, credentialSubject } = credential

      const matchesSessionDid = didUri === credentialSubject.id
      if (!matchesSessionDid) {
        return false
      }

      Did.Utils.validateKiltDidUri(credentialSubject.id)
      const matchesIssuer = issuer === credentialSubject.id
      if (!matchesIssuer) {
        return false
      }

      const matchesOrigin = origin === credentialSubject.origin
      if (!matchesOrigin) {
        return false
      }
      const fullDid = await Did.resolve(didUri)

      if (!fullDid?.document) {
        throw new Error('No Did found: Please create a Full DID')
      }

      const { document } = fullDid

      if (!document?.assertionMethod?.[0].id) {
        throw new Error('No DID attestation key on-chain')
      }

      const { verified } = await Did.verifyDidSignature({
        expectedVerificationMethod: 'assertionMethod',
        signature: {
          keyUri: credential.proof.verificationMethod,
          signature: credential.proof.signature as string,
        },
        message: Utils.Crypto.coToUInt8(credentialSubject.rootHash),
      })
      return verified
    }
  )
  if (!verified) {
    throw new Error(
      `Verification of DID configuration resource of ${origin} failed for ${didUri}`
    )
  }
}
