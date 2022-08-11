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
} from '@kiltprotocol/sdk-js'

export const DEFAULT_VERIFIABLECREDENTIAL_TYPE = 'VerifiableCredential'
export const KILT_VERIFIABLECREDENTIAL_TYPE = 'KiltCredential2020'
export const KILT_SELF_SIGNED_PROOF_TYPE = 'KILTSelfSigned2020'

export async function createWellKnownDidConfig(
  sign: SignCallback,
  origin: string,
  didUri: string
): Promise<ICredential> {
  const fullDid = await Did.FullDidDetails.fromChainInfo(didUri)

  if (!fullDid) throw new Error('No Did found: Please create a Full DID')

  const ctypeDomainLinkage = CType.fromSchema({
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

  const domainClaimContents = {
    id: fullDid.did,
    origin,
  }

  const claim = Claim.fromCTypeAndClaimContents(
    ctypeDomainLinkage,
    domainClaimContents,
    fullDid.did
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
    fullDid.did
  )

  return Credential.fromRequestAndAttestation(request, attestation)
}

export function getDidConfiguration(
  credential: ICredential,
  expirationDate?: string
) {
  const credentialSubject = {
    ...credential.request.claim.contents,
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

  if (!claimerSignature)
    throw new Error('No Claimer Signature found in the credential')

  // add self-signed proof
  const proof = {
    type: KILT_SELF_SIGNED_PROOF_TYPE,
    proofPurpose: 'assertionMethod',
    verificationMethod: claimerSignature.keyId,
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
