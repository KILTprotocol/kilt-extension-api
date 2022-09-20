import {
  RequestForAttestation,
  Did,
  KeyRelationship,
  CType,
  Credential,
  Attestation,
  Claim,
  ICredential,
  KeystoreSigner as SignCallback,
  DidUri,
  Utils,
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
  sign: SignCallback,
  origin: string,
  didUri: DidUri
): Promise<ICredential> {
  const fullDid = await Did.FullDidDetails.fromChainInfo(didUri)

  if (!fullDid) throw new Error('No Did found: Please create a Full DID')

  if (!(await ctypeDomainLinkage.verifyStored()))
    throw new Error('Domain Linkage claim type not found on chain')

  const domainClaimContents = {
    id: fullDid.uri,
    origin,
  }

  const claim = Claim.fromCTypeAndClaimContents(
    ctypeDomainLinkage,
    domainClaimContents,
    fullDid.uri
  )

  const request = RequestForAttestation.fromClaim(claim)

  const assertionKey = fullDid.getVerificationKeys(
    KeyRelationship.assertionMethod
  )[0]

  if (!assertionKey)
    throw new Error(
      'Full DID doesnt have assertion key: Please add assertion key'
    )

  const selfSignedRequest = await request.signWithDidKey(
    sign,
    fullDid,
    assertionKey.id
  )

  const attestation = Attestation.fromRequestAndDid(
    selfSignedRequest,
    fullDid.uri
  )

  return Credential.fromRequestAndAttestation(request, attestation)
}

export function getDomainLinkagePresentation(
  credential: ICredential,
  expirationDate?: string
): VerifiableDomainLinkagePresentation {
  const claimContents = credential.request.claim.contents
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
    rootHash: credential.request.rootHash,
  }

  const issuer = credential.attestation.owner

  const issuanceDate = new Date().toISOString()

  if (!expirationDate) {
    expirationDate = new Date(
      Date.now() + 1000 * 60 * 60 * 24 * 365 * 5
    ).toISOString() // 5 years
  }

  const { claimerSignature } = credential.request

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

      const isDid = Did.Utils.validateKiltDidUri(credentialSubject.id)
      const matchesIssuer = issuer === credentialSubject.id
      if (!isDid || !matchesIssuer) {
        return false
      }

      const matchesOrigin = origin === credentialSubject.origin
      if (!matchesOrigin) {
        return false
      }
      const didDetails = await Did.FullDidDetails.fromChainInfo(issuer)
      if (!didDetails) {
        throw new Error('No on-chain did')
      }

      if (!didDetails.attestationKey) {
        throw new Error('No DID attestation key on-chain')
      }

      const { verified } = await Did.verifyDidSignature({
        signature: {
          keyUri: didDetails.assembleKeyUri(didDetails.attestationKey.id),
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
