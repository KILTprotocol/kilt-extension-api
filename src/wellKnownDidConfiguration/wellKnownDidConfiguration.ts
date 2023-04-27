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
import {
  CredentialSubject,
  DomainLinkageCredential,
  VerifiableDomainLinkagePresentation,
} from '../types/types'
import * as validUrl from 'valid-url'
import { SelfSignedProof, constants } from '@kiltprotocol/vc-export'
import { hexToU8a, isHex } from '@polkadot/util'

const {
  DEFAULT_VERIFIABLECREDENTIAL_TYPE,
  KILT_VERIFIABLECREDENTIAL_TYPE,
  KILT_SELF_SIGNED_PROOF_TYPE,
  DEFAULT_VERIFIABLECREDENTIAL_CONTEXT,
  KILT_CREDENTIAL_IRI_PREFIX,
} = constants

export {
  DEFAULT_VERIFIABLECREDENTIAL_TYPE,
  KILT_VERIFIABLECREDENTIAL_TYPE,
  KILT_SELF_SIGNED_PROOF_TYPE,
  DEFAULT_VERIFIABLECREDENTIAL_CONTEXT as DID_VC_CONTEXT,
}
export const DID_CONFIGURATION_CONTEXT =
  'https://identity.foundation/.well-known/did-configuration/v1'

export const ctypeDomainLinkage = CType.fromProperties(
  'Domain Linkage Credential',
  {
    origin: {
      type: 'string',
    },
  }
)

export async function createCredential(
  signCallback: SignCallback,
  origin: string,
  didUri: DidUri
): Promise<ICredentialPresentation> {
  const fullDid = await Did.resolve(didUri)

  if (!fullDid?.document) {
    throw new Error('No Did found: Please create a Full DID')
  }

  const { document } = fullDid

  if (!validUrl.isUri(origin)) {
    throw new Error('The origin is not a valid url')
  }

  const domainClaimContents = {
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
    signCallback,
  })
}

export async function getDomainLinkagePresentation(
  credential: ICredentialPresentation,
  expirationDate: string = new Date(
    Date.now() + 1000 * 60 * 60 * 24 * 365 * 5
  ).toISOString()
): Promise<VerifiableDomainLinkagePresentation> {
  const claimContents = credential.claim.contents
  if (!credential.claim.owner && !claimContents.origin) {
    throw new Error('Claim do not content an owner or origin')
  }

  Did.validateUri(credential.claim.owner)

  const didUri = credential.claim.owner

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
  }

  const issuanceDate = new Date().toISOString()

  const { claimerSignature, rootHash } = credential

  const id = KILT_CREDENTIAL_IRI_PREFIX + credential.rootHash

  await Did.verifyDidSignature({
    expectedVerificationMethod: 'assertionMethod',
    signature: hexToU8a(claimerSignature.signature),
    keyUri: claimerSignature.keyUri,
    message: Utils.Crypto.coToUInt8(rootHash),
  })

  // add self-signed proof
  const proof: SelfSignedProof = {
    type: KILT_SELF_SIGNED_PROOF_TYPE,
    proofPurpose: 'assertionMethod',
    verificationMethod: claimerSignature.keyUri,
    signature: claimerSignature.signature,
    challenge: claimerSignature.challenge,
  }

  return {
    '@context': DID_CONFIGURATION_CONTEXT,
    linked_dids: [
      {
        '@context': [
          'https://www.w3.org/2018/credentials/v1',
          DID_CONFIGURATION_CONTEXT,
        ],
        id,
        issuer: didUri,
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
  verify: (credential: DomainLinkageCredential) => Promise<void>
) {
  await Promise.all(credentials.map((credential) => verify(credential)))
}

export async function verifyDidConfigPresentation(
  didUri: DidUri,
  domainLinkageCredential: VerifiableDomainLinkagePresentation,
  origin: string
): Promise<void> {
  // Verification steps outlined in Well Known DID Configuration
  // https://identity.foundation/.well-known/resources/did-configuration/#did-configuration-resource-verification

  await asyncSome(domainLinkageCredential.linked_dids, async (credential) => {
    const { issuer, credentialSubject, id } = credential

    const matchesSessionDid = didUri === credentialSubject.id
    if (!matchesSessionDid) throw new Error('session did doesnt match')

    Did.validateUri(credentialSubject.id)
    const matchesIssuer = issuer === credentialSubject.id
    if (!matchesIssuer) throw new Error('does not match the issuer')

    const matchesOrigin = origin === credentialSubject.origin
    if (!matchesOrigin) throw new Error('does not match the origin')
    if (!validUrl.isUri(origin)) throw new Error('not a valid uri')

    const fullDid = await Did.resolve(didUri)

    if (!fullDid?.document) {
      throw new Error('No Did found: Please create a Full DID')
    }

    const { document } = fullDid

    if (!document?.assertionMethod?.[0].id) {
      throw new Error('No DID attestation key on-chain')
    }

    // Stripping off the prefix to get the root hash
    const rootHash = id.substring(KILT_CREDENTIAL_IRI_PREFIX.length)
    if (!isHex(rootHash)) {
      throw new Error(
        'Credential id is not a valid identifier (could not extract base16 / hex encoded string)'
      )
    }

    await Did.verifyDidSignature({
      expectedVerificationMethod: 'assertionMethod',
      signature: hexToU8a(credential.proof.signature),
      keyUri: credential.proof.verificationMethod as DidResourceUri,
      message: Utils.Crypto.coToUInt8(rootHash),
    })
  })
}
