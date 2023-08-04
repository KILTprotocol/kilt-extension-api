import type { KiltAddress } from './Address'
import type { BN } from './Imported'
/**
 * A string containing a KILT DID Uri.
 */

type DidUriVersion = '' | `v${string}:`
type AuthenticationKeyType = '00' | '01'
type LightDidEncodedData = '' | `:${string}`

/**
 * DID keys are purpose-bound. Their role or purpose is indicated by the verification or key relationship type.
 */
const keyRelationshipsC = ['authentication', 'capabilityDelegation', 'assertionMethod', 'keyAgreement'] as const
export const keyRelationships = keyRelationshipsC as unknown as string[]
export type KeyRelationship = (typeof keyRelationshipsC)[number]

export type DidUri =
  | `did:kilt:${DidUriVersion}${KiltAddress}`
  | `did:kilt:light:${DidUriVersion}${AuthenticationKeyType}${KiltAddress}${LightDidEncodedData}`

/**
 * The fragment part of the DID URI including the `#` character.
 */
export type UriFragment = `#${string}`
/**
 * URI for DID resources like keys or service endpoints.
 */
export type DidResourceUri = `${DidUri}${UriFragment}`

export type DidSignature = {
  keyUri: DidResourceUri
  signature: string
}

/**
 * The SDK-specific base details of a DID key.
 */
export type BaseDidKey = {
  /**
   * Relative key URI: `#` sign followed by fragment part of URI.
   */
  id: UriFragment
  /**
   * The public key material.
   */
  publicKey: Uint8Array
  /**
   * The inclusion block of the key, if stored on chain.
   */
  includedAt?: BN
  /**
   * The type of the key.
   */
  type: string
}

/**
 * Possible types for a DID encryption key.
 */
const encryptionKeyTypesC = ['x25519'] as const
export const encryptionKeyTypes = encryptionKeyTypesC as unknown as string[]
export type EncryptionKeyType = (typeof encryptionKeyTypesC)[number]

/**
 * Possible types for a DID verification key.
 */
const verificationKeyTypesC = ['sr25519', 'ed25519', 'ecdsa'] as const
export const verificationKeyTypes = verificationKeyTypesC as unknown as string[]
export type VerificationKeyType = (typeof verificationKeyTypesC)[number]

/**
 * The SDK-specific details of a DID verification key.
 */
export type DidVerificationKey = BaseDidKey & { type: VerificationKeyType }
/**
 * The SDK-specific details of a DID encryption key.
 */
export type DidEncryptionKey = BaseDidKey & { type: EncryptionKeyType }
/**
 * The SDK-specific details of a DID key.
 */
export type DidKey = DidVerificationKey | DidEncryptionKey

/**
 * The SDK-specific details of a new DID service endpoint.
 */
export type DidServiceEndpoint = {
  /**
   * Relative endpoint URI: `#` sign followed by fragment part of URI.
   */
  id: UriFragment
  /**
   * A list of service types the endpoint exposes.
   */
  type: string[]
  /**
   * A list of URIs the endpoint exposes its services at.
   */
  serviceEndpoint: string[]
}

export interface DidDocument {
  uri: DidUri

  authentication: [DidVerificationKey]
  assertionMethod?: [DidVerificationKey]
  capabilityDelegation?: [DidVerificationKey]
  keyAgreement?: DidEncryptionKey[]

  service?: DidServiceEndpoint[]
}

export type BaseNewDidKey = {
  publicKey: Uint8Array
  type: string
}


export type NewDidVerificationKey = BaseNewDidKey & {
  type: VerificationKeyType
}

export type LightDidSupportedVerificationKeyType = Extract<
  VerificationKeyType,
  'ed25519' | 'sr25519'
>

export type NewLightDidVerificationKey = NewDidVerificationKey & {
  type: LightDidSupportedVerificationKeyType
}
